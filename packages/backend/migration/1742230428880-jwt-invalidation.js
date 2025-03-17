/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

export class JWTInvalidation1742230428880 {
    name = 'JWTInvalidation1742230428880';

    async up(queryRunner) {
        await queryRunner.query(`CREATE TABLE "jwt_invalidation" (
            "userId" VARCHAR(255) NOT NULL,
            "serial" INTEGER NOT NULL,
            "revoked_at" TIMESTAMP WITH TIME ZONE NOT NULL,
            "applyToPrevious" BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY ("userId", "serial")
        )`);
    }

    async down(queryRunner) {
        await queryRunner.query(`DROP TABLE "jwt_invalidation"`);
    }
}
