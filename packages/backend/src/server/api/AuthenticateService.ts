/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { Inject, Injectable, OnApplicationShutdown } from '@nestjs/common';
import { DI } from '@/di-symbols.js';
import type { AccessTokensRepository, AppsRepository, JWTTokenInvalidationsRepository, UsersRepository } from '@/models/_.js';
import { MiUser, type MiLocalUser } from '@/models/User.js';
import type { MiAccessToken } from '@/models/AccessToken.js';
import { MemoryKVCache } from '@/misc/cache.js';
import type { MiApp } from '@/models/App.js';
import { CacheService } from '@/core/CacheService.js';
import { bindThis } from '@/decorators.js';
import { RuntimeSecretService } from '@/core/crypto/RuntimeSecretService.js';
import { createSecretKey, KeyObject } from 'crypto';
import { isLegacyUserToken } from '@/core/crypto/LegacyToken.js';
import { type Config } from '@/config.js';
import jwt from 'jsonwebtoken';
import { RoleService } from '@/core/RoleService.js';
import { LoggerService } from '@/core/LoggerService.js';
import Logger from '@/logger.js';


const JWT_REGEXP = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;

// force all session to be renewed every 180 days
const ABSOLUTE_BOUNDING_EXPIRATION = 180 * 24 * 60 * 60;

//#region Meta token policies for broad access control already in the architecture

// User session token
export const KIND_USER_SESSION = 'meta:user:session';

// Access API endpoints with moderator ACL (requireModerator)
export const KIND_MODERATOR_ACL = 'meta:moderator:acl';

// Access API endpoints with admin ACL (requireAdmin)
export const KIND_ADMIN_ACL = 'meta:admin:acl';

// Overrides DAC (ownership) checks for moderators
export const KIND_MODERATOR_DAC_OVERRIDE = 'meta:moderator:dac_override';

// Override RBAC (role) checks for API endpoints
export const KIND_ADMIN_RBAC_OVERRIDE = 'meta:admin:rbac_override';

//#endregion

export type TokenClass = 'legacy_user' | 'legacy_app' | 'jwt';

export type AudienceBasePath = (string & {}) | '/api/';

export class AuthenticationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'AuthenticationError';
	}
}

export type TokenParam = {
	user_id: string;
	app_id: string | null;
	bounding_expiration: number | null; // absolute time when the token will be expired even with renewal
	audience: AudienceBasePath[];

	policy: string[]; // actions allowed for this token
	deny_policy: string[]; // actions not allowed for this token
	sudo_policy: string[]; // actions allowed for this token when elevated temporarily using a password
}

export interface TokenInfo {
	not_after: number | null; // expiration time if not renewed
	class: TokenClass;
	serial: number;
	is_sudo: boolean;
}

@Injectable()
export class AuthenticateService implements OnApplicationShutdown {
	private appCache: MemoryKVCache<MiApp>;
	private sudoCache: MemoryKVCache<number>;
	private signingKey: KeyObject;
	private primaryKeyId: string;
	private logger: Logger;

	constructor(
		@Inject(DI.config)
		private config: Config,

		@Inject(DI.usersRepository)
		private usersRepository: UsersRepository,

		@Inject(DI.accessTokensRepository)
		private accessTokensRepository: AccessTokensRepository,

		@Inject(DI.appsRepository)
		private appsRepository: AppsRepository,

		@Inject(DI.jwtTokenInvalidationsRepository)
		private jwtTokenInvalidationsRepository: JWTTokenInvalidationsRepository,

		@Inject(DI.runtimeSecretService)
		private runtimeSecretService: RuntimeSecretService,

		private roleService: RoleService,

		private cacheService: CacheService,

		private loggerService: LoggerService,

	) {
		this.logger = this.loggerService.getLogger('authenticate');

		this.appCache = new MemoryKVCache<MiApp>(1000 * 60 * 60 * 24 * 7); // 1w
		this.sudoCache = new MemoryKVCache<number>(1000 * 60 * 60); // 1h

		const secret = this.runtimeSecretService.getRuntimeSecret('TokenDispatchService', 'signingKey', 384 / 8);
		this.signingKey = createSecretKey(secret);
		this.primaryKeyId = this.runtimeSecretService.computeSecretChecksum().slice(0, 8);
	}

	@bindThis
	private async verifyLegacyUserToken(token: string): Promise<MiLocalUser> {
		const user = await this.cacheService.localUserByNativeTokenCache.fetch(token,
			() => this.usersRepository.findOneBy({ token }) as Promise<MiLocalUser | null>);

		if (user == null) {
			throw new AuthenticationError('user not found');
		}

		return user;
	}

	@bindThis
	private async verifyLegacyAppToken(token: string): Promise<[MiLocalUser, MiAccessToken]> {
		const accessToken = await this.accessTokensRepository.findOne({
			where: [{
				hash: token.toLowerCase(), // app
			}, {
				token: token, // miauth
			}],
		});

		if (accessToken == null) {
			throw new AuthenticationError('invalid signature');
		}

		this.accessTokensRepository.update(accessToken.id, {
			lastUsedAt: new Date(),
		});

		const user = await this.cacheService.localUserByIdCache.fetch(accessToken.userId,
			() => this.usersRepository.findOneBy({
				id: accessToken.userId,
			}) as Promise<MiLocalUser>);

		if (accessToken.appId) {
			const app = await this.appCache.fetch(accessToken.appId,
				() => this.appsRepository.findOneByOrFail({ id: accessToken.appId! }));

			return [user, {
				id: accessToken.id,
				permission: app.permission,
			} as MiAccessToken];
		} else {
			return [user, accessToken];
		}
	}

	@bindThis
	private async verifyJWTToken(token: string): Promise<[MiLocalUser, TokenParam & TokenInfo]> {
		const payload = jwt.verify(token, this.signingKey, {
			clockTolerance: 120,
			algorithms: ['HS256', 'HS384', 'HS512'],
			issuer: this.config.url,
		});

		if (typeof payload === 'string') {
			throw new AuthenticationError('Invalid token');
		}

		if (typeof payload.sub !== 'string') {
			throw new AuthenticationError('Invalid token, missing sub');
		}

		if (typeof payload.exp !== 'number') {
			throw new AuthenticationError('Invalid token, missing exp');
		}

		if (typeof payload.jti !== 'string') {
			throw new AuthenticationError('Invalid token, missing jti');
		}

		if (!payload.aud) {
			throw new AuthenticationError('Invalid token, missing audience');
		}

		// https://www.npmjs.com/package/jsonwebtoken#token-expiration-exp-claim
		const now = Math.floor(Date.now() / 1000);
		if (!payload.iat || payload.iat > now + ABSOLUTE_BOUNDING_EXPIRATION) {
			throw new AuthenticationError('Token past absolute TTL, please login or recreate your session');
		}

		if (payload.mkBoundingExp) {
			if (typeof payload.mkBoundingExp !== 'number') {
				throw new AuthenticationError('Invalid token, mkBoundingExp is not a number');
			}

			if (payload.iat > now + payload.mkBoundingExp) {
				throw new AuthenticationError('Token past absolute TTL, please login or recreate your session');
			}
		}

		const id = parseInt(payload.jti.split(':')[1]);
		if (isNaN(id)) {
			throw new AuthenticationError('Invalid token, missing serial');
		}

		const param: TokenParam = {
			audience: typeof payload.aud === 'string' ? [payload.aud] : payload.aud,
			user_id: payload.sub,
			app_id: payload.mkAppId,
			bounding_expiration: payload.mkBoundingExp,
			policy: payload.mkPolicy ?? [],
			deny_policy: payload.mkDenyPolicy ?? [],
			sudo_policy: payload.mkSudoPolicy ?? [],
		}

		let is_sudo = false;
		const sudo_until = this.sudoCache.get(payload.jti);
		if (sudo_until && +new Date() < sudo_until) {
			is_sudo = true;
		}

		const info: TokenInfo = {
			not_after: payload.exp,
			class: 'jwt',
			serial: id,
			is_sudo,
		}

		// check for invalidations
		const invalidations = await this.jwtTokenInvalidationsRepository.find({
			where: {
				userId: param.user_id,
				serial: id,
			},
		});

		if (invalidations.length > 0) {
			throw new AuthenticationError('Token has been revoked');
		}

		const user = await this.cacheService.localUserByIdCache.fetch(param.user_id,
			() => this.usersRepository.findOneBy({ id: param.user_id }) as Promise<MiLocalUser>);

		return [user, { ...param, ...info }];
	}

	@bindThis
	private applyTokenClassConstraint(info: TokenParam & TokenInfo) {
		if (info.class === 'legacy_user') {
			switch (this.config.legacyTokenBehavior) {
				case 'allow':
					break;
				case 'no_admin':
					info.sudo_policy = [];
					info.deny_policy.push('meta:admin:', 'meta:moderator:');
					break;
				case 'deny':
					throw new AuthenticationError('Legacy user token is no longer accepted');
			}
		}
	}

	@bindThis
	private applyRoleConstraint(info: TokenParam & TokenInfo) {
		if (!this.roleService.isModerator({ id: info.user_id })) {
			info.policy = info.policy.filter(p => !p.includes(':moderator:') && !p.includes(':admin:'));
			info.sudo_policy = info.sudo_policy.filter(p => !p.includes(':moderator:') && !p.includes(':admin:'));
			info.deny_policy.push('meta:moderator:', 'read:admin:', 'write:admin:');
		}
		if (!this.roleService.isAdministrator({ id: info.user_id })) {
			info.policy = info.policy.filter(p => !p.includes(':admin:'));
			info.sudo_policy = info.sudo_policy.filter(p => !p.includes(':admin:'));
			info.deny_policy.push('meta:admin:', 'read:admin:', 'write:admin:');
		}
	}

	@bindThis
	public async hasPolicy(auth: TokenParam & TokenInfo, alternatives: string | string[]): Promise<boolean> {
		if (typeof alternatives === 'string') {
			alternatives = [alternatives];
		}

		if (auth.deny_policy.some(p => alternatives.some(a => a.startsWith(p)))) {
			return false;
		}


		if (auth.policy.some(p => alternatives.some(a => a.startsWith(p)))) {
			return true;
		}

		const sudoed = this.sudoCache.get(`${auth.user_id}:${auth.serial}`);
		if (sudoed && auth.sudo_policy.some(p => alternatives.some(a => a.startsWith(p)))) {
			return true;
		}

		return false;
	}

	@bindThis
	public async authAndRenewJWTToken(token: string, desiredTTL: string | number = '90d'): Promise<[MiLocalUser, TokenParam & TokenInfo, string]> {
		const authResult = await this.authenticate(token);
		if (!authResult) {
			throw new AuthenticationError('token is no longer valid');
		}

		const [user, info] = authResult;

		const newToken = await this.signToken(user, info, {
			basePath: info.audience,
			ttl: desiredTTL,
		});

		return [user, info, newToken];
	}


	@bindThis
	public async authenticate(token: string | null | undefined): Promise<[MiLocalUser, TokenParam & TokenInfo] | null> {
		if (token == null) {
			return null;
		}

		let user: MiLocalUser;
		let info: TokenParam & TokenInfo;

		if (isLegacyUserToken(token)) {
			user = await this.verifyLegacyUserToken(token);
			if (user == null) {
				return null;
			}

			info = {
				not_after: null,
				audience: ['/api/'],
				app_id: null,
				class: 'legacy_user',
				serial: 0,
				user_id: user.id,
				bounding_expiration: null,
				policy: [KIND_MODERATOR_DAC_OVERRIDE, KIND_ADMIN_RBAC_OVERRIDE],
				deny_policy: [],
				sudo_policy: [],
				is_sudo: false,
			}


		} else if (JWT_REGEXP.test(token)) {
			[user, info] = await this.verifyJWTToken(token);
		} else {
			let accessToken;
			[user, accessToken] = await this.verifyLegacyAppToken(token);

			info = {
				not_after: null,
				app_id: accessToken.appId,
				class: 'legacy_app',
				serial: 0,
				audience: ['/api/'],
				user_id: user.id,
				bounding_expiration: null,
				policy: accessToken.permission,
				deny_policy: [],
				sudo_policy: [],
				is_sudo: false,
			}
		}

		this.applyTokenClassConstraint(info);
		this.applyRoleConstraint(info);

		return [user, info];
	}

	@bindThis
	public async signToken(user: MiLocalUser, param: TokenParam, {
		basePath,
		ttl,
	}: {
		basePath: AudienceBasePath | AudienceBasePath[],
		ttl: string | number,
	} = {
			basePath: '/api/',
			ttl: '90d',
		}): Promise<string> {
		const serial = await this.usersRepository.createQueryBuilder()
			.update(MiUser)
			.set({
				jwt_serial_counter: () => 'jwt_serial_counter + 1',
			})
			.where('id = :id', { id: user.id })
			.returning('jwt_serial_counter')
			.execute();

		const newSerial = serial.raw?.[0]?.jwt_serial_counter;

		if (typeof newSerial !== 'number') {
			throw new Error('Failed to increment serial');
		}


		return jwt.sign({
			mkAppId: param.app_id,
			mkBoundingExp: param.bounding_expiration,
			mkPolicy: param.policy,
			mkDenyPolicy: param.deny_policy,
			mkSudoPolicy: param.sudo_policy,
		}, this.signingKey, {
			algorithm: 'HS384',
			expiresIn: ttl, audience: basePath,
			issuer: this.config.url,
			subject: user.id,
			keyid: this.primaryKeyId,
			jwtid: `${user.id}:${newSerial}`,
		});
	}

	@bindThis
	public async revokeToken(userId: string, serial: number, cascadeBefore: boolean = false): Promise<void> {
		await this.jwtTokenInvalidationsRepository.save({
			userId,
			serial,
			revokedAt: new Date(),
			applyToPrevious: cascadeBefore,
		});

		try {
			if (cascadeBefore) {
				// delete useless entries
				await this.jwtTokenInvalidationsRepository.createQueryBuilder()
					.delete()
					.where('userId = :userId', { userId })
					.andWhere('serial < :serial', { serial })
					.execute();
			}

			// garbage collect invalidations that are 100% past their expiration (past the global absolute TTL plus 1 day of additional drift tolerance)
			await this.jwtTokenInvalidationsRepository.createQueryBuilder()
				.delete()
				.where('userId = :userId', { userId })
				.andWhere('revokedAt < :now', { now: new Date(Date.now() - 1000 * ABSOLUTE_BOUNDING_EXPIRATION - 24 * 3600_000) })
				.execute();
		} catch (e) {
			this.logger.warn('Failed to garbage collect invalidations', { error: e });
			if (process.env.NODE_ENV !== 'production') {
				throw e;
			}
		}
	}

	@bindThis
	public async setSudo(jwtid: string, until: number | null = null): Promise<void> {
		this.sudoCache.set(jwtid, until ?? +new Date() + 1000 * 60 * 60);
	}

	@bindThis
	public dispose(): void {
		this.appCache.dispose();
	}

	@bindThis
	public onApplicationShutdown(signal?: string | undefined): void {
		this.dispose();
	}
}
