/*
 * SPDX-FileCopyrightText: syuilo and misskey-project
 * SPDX-License-Identifier: AGPL-3.0-only
 */

export class RuntimeSecret1742174378165 {
    name = 'RuntimeSecret1742174378165';

    async up(queryRunner) {
        await queryRunner.query(`ALTER TABLE "meta" ADD COLUMN "runtime_secret" VARCHAR(255) NOT NULL DEFAULT ''`);
        await queryRunner.query(`ALTER TABLE "meta" ADD COLUMN "runtime_secret_checksum" VARCHAR(255) NOT NULL DEFAULT ''`);
        await queryRunner.query(`ALTER TABLE "user" ADD COLUMN "jwt_serial_counter" INTEGER NOT NULL DEFAULT 0`);
    }

    async down(queryRunner) {
        await queryRunner.query(`ALTER TABLE "meta" DROP COLUMN "runtime_secret"`);
        await queryRunner.query(`ALTER TABLE "meta" DROP COLUMN "runtime_secret_checksum"`);
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "jwt_serial_counter"`);
    }
}
