/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import { Entity, PrimaryColumn, Index, Column, ManyToOne, JoinColumn } from 'typeorm';
import { id } from './util/id.js';

@Entity('jwt_token_invalidation')
export class MiJWTTokenInvalidation {
	@PrimaryColumn(id())
	public userId: string;

	@PrimaryColumn('integer', {
		default: 0,
	})
	public serial: number;

	@Column('boolean', {
		default: false,
		comment: 'Whether tokens with serial less than this entry should also be invalidated',
	})
	public applyToPrevious: boolean;

	@Column('timestamp with time zone', {
		comment: 'The time when the token was revoked for garbage collection',
	})
	public revokedAt: Date | null;
}
