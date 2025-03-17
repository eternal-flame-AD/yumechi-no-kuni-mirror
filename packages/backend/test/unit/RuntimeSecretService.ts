/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

process.env.NODE_ENV = 'test';

import { Test } from '@nestjs/testing';
import { GlobalModule } from '@/GlobalModule.js';
import { DI } from '@/di-symbols.js';
import { RuntimeSecretService } from '@/core/crypto/RuntimeSecretService.js';
import { CoreModule } from '@/core/CoreModule.js';
import type { TestingModule } from '@nestjs/testing';
import type { DataSource } from 'typeorm';
import { MiMeta } from '@/models/Meta.js';
import { Config } from '@/config.js';

describe('RuntimeSecretService', () => {
	let app: TestingModule;
	let runtimeSecretService: RuntimeSecretService;
	let db: DataSource;

	beforeAll(async () => {
		app = await Test.createTestingModule({
			imports: [
				GlobalModule,
				CoreModule,
			],
		}).compile();

		app.enableShutdownHooks();

		runtimeSecretService = app.get<RuntimeSecretService>(DI.runtimeSecretService, { strict: false });
		db = app.get<DataSource>(DI.db);
	});

	afterAll(async () => {
		await app.close();
	});

	test('initialize (new instance)', async () => {
		await runtimeSecretService.initialize();
		
		// Verify meta row was created with persistent secret
		const meta = await db.getRepository(MiMeta).findOne({
			where: { id: 'x' },
		});
		expect(meta?.persistentSecret).toBeDefined();
		expect(meta?.persistentSecretChecksum).toBeDefined();
	});

	test('validate checksum', async () => {
		await runtimeSecretService.initialize();

		const meta = await db.getRepository(MiMeta).findOne({
			where: { id: 'x' },
		});

		const isValid = await runtimeSecretService.validate(meta?.persistentSecretChecksum ?? '');
		expect(isValid).toBe(true);
	});

	test('validate with incorrect checksum', async () => {
		await runtimeSecretService.initialize();

		const isValid = await runtimeSecretService.validate('incorrect-checksum');
		expect(isValid).toBe(false);
	});

	test('getRuntimeSecret', async () => {
		await runtimeSecretService.initialize();

		const secret = runtimeSecretService.getRuntimeSecret('test-module', 'test-id');
		expect(secret).toBeInstanceOf(Buffer);
		expect(secret.length).toBe(32); // KEY_LENGTH = 256/8 = 32
	});

	test('getRuntimeSecret consistency', async () => {
		const config = app.get<Config>(DI.config);
		const newRuntimeSecretService = new RuntimeSecretService(config, db);
		await newRuntimeSecretService.initialize();

		const secret1 = runtimeSecretService.getRuntimeSecret('test-module', 'test-id');
		const secret2 = newRuntimeSecretService.getRuntimeSecret('test-module', 'test-id');
		expect(secret1).toEqual(secret2);
	});

	test('setup external IKM', async () => {
		const newConfig = app.get<Config>(DI.config);
		newConfig.externalIkm = [{
			pass: 'test-password',
		}];
		
		const originalSecretChecksum = runtimeSecretService.computeSecretChecksum();
		const originalSecret = runtimeSecretService.getRuntimeSecret('test-module', 'test-id');
		const newRuntimeSecretService = new RuntimeSecretService(newConfig, db);
		await newRuntimeSecretService.initialize();
		const newSecret = newRuntimeSecretService.getRuntimeSecret('test-module', 'test-id');
		const newSecretChecksum = newRuntimeSecretService.computeSecretChecksum();

		expect(originalSecret).toEqual(newSecret);
		expect(originalSecretChecksum).toEqual(newSecretChecksum);
	});

	test('zeroize', async () => {
		await runtimeSecretService.initialize();

		runtimeSecretService.zeroize();
		
		// Attempting to get a runtime secret after zeroize should throw
		expect(() => {
			runtimeSecretService.getRuntimeSecret('test-module', 'test-id');
		}).toThrow('Runtime secret service not initialized');
	});
}); 