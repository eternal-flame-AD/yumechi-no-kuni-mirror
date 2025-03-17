import { DI } from "@/di-symbols.js";
import { Inject, Injectable } from "@nestjs/common";
import { ExternalIKMConfig, type Config } from "@/config.js";
import { MiMeta } from "@/models/Meta.js";
import { DataSource } from "typeorm";
import { hkdfSync } from "node:crypto";
import fs from "node:fs";

@Injectable()
export class RuntimeSecretService {
    private readonly KEY_LENGTH = 256 / 8;
    private persistentSecret: Buffer | null = null;

    constructor(
        @Inject(DI.config)
        private config: Config,

        @Inject(DI.db)
        private db: DataSource,
    ) {
    }

    public computeSecretChecksum(): string {
        if (!this.persistentSecret) {
            throw new Error('Runtime secret service not initialized');
        }

        const okm = hkdfSync(
            'sha512',
            this.persistentSecret, // IKM
            Buffer.from(this.config.url), // salt
            'Product: misskey\r\nSecret-Type: secret-checksum\r\n', // info
            this.KEY_LENGTH,
        );

        return Buffer.from(okm).toString('base64');
    }

    /**
     * Validate a checksum against the persistent secret currently set in memory
     * @param checksum - The checksum to validate
     * @returns True if the checksum is valid, false otherwise
     */
    public async validate(checksum: string): Promise<boolean> {
        if (!this.persistentSecret) {
            throw new Error('Persistent secret not loaded');
        }

        const actualChecksum = this.computeSecretChecksum();

        return checksum === actualChecksum;
    }

    /**
     * Load the persistent secret from the database, applying external IKM sources if present
     */
    public async initialize() {
        if (this.persistentSecret) {
            return;
        }

        // if we don't have a persistent secret, generate one
        await this.db.transaction(async transactionalEntityManager => {
            const existingMeta = await transactionalEntityManager.findOne(MiMeta, {
                where: {
                    id: 'x',
                },
            });

            if (!existingMeta) {
                throw new Error('Meta row not found in database, did you run migrations?');
            }

            if (existingMeta.persistentSecret) {
                this.persistentSecret = Buffer.from(existingMeta.persistentSecret, 'base64');

                let firstExternalIKMSetupSecretBackup = null;
                if (existingMeta.persistentSecretChecksum === this.computeSecretChecksum() && this.config.externalIkm.length > 0) {
                    // external IKM was just set up, we need to update the persistent secret
                    firstExternalIKMSetupSecretBackup = Buffer.from(this.persistentSecret);
                }

                for (const input of this.config.externalIkm) {
                    this.mixinExternalIKM(input);
                }

                if (firstExternalIKMSetupSecretBackup) {
                    // now backup IS the correct secret (we just applied the external IKM pad to this.persistentSecret)
                    // this.persistentSecret is the one supposed to be in the DB , so swap it
                    [this.persistentSecret, firstExternalIKMSetupSecretBackup] = [firstExternalIKMSetupSecretBackup, this.persistentSecret];
                    if (existingMeta.persistentSecretChecksum !== this.computeSecretChecksum()) {
                        throw new Error('Sanity check failed when trying to apply external IKM, this is a bug');
                    }
                    existingMeta.persistentSecret = firstExternalIKMSetupSecretBackup.toString('base64');
                    await transactionalEntityManager.save(existingMeta);
                } else if (existingMeta.persistentSecretChecksum) {
                    if (!await this.validate(existingMeta.persistentSecretChecksum)) {
                        throw new Error('Persistent secret checksum mismatch, did you have incorrect external IKM sources?');
                    }
                } else {
                    existingMeta.persistentSecretChecksum = this.computeSecretChecksum();
                    await transactionalEntityManager.save(existingMeta);
                }
            } else {
                const newDBPersistentSecret = Buffer.alloc(this.KEY_LENGTH);
                crypto.getRandomValues(newDBPersistentSecret);
                this.persistentSecret = newDBPersistentSecret;
                existingMeta.persistentSecret = this.persistentSecret.toString('base64');

                for (const input of this.config.externalIkm) {
                    this.mixinExternalIKM(input);
                }

                existingMeta.persistentSecretChecksum = this.computeSecretChecksum();

                await transactionalEntityManager.save(existingMeta);
            }
        });
    }
    
    private mixinExternalIKM(input: ExternalIKMConfig) {
        if (!this.persistentSecret) {
            throw new Error('Runtime secret service not initialized');
        }

        let secret;
        let source;

        if ('env' in input) {
            secret = process.env[input.env];
            source = `env: ${input.env}`;
        } else if ('file' in input) {
            secret = fs.readFileSync(input.file, 'utf8').trim();
            source = `file: ${input.file}`;
        } else if ('pass' in input) {
            secret = input.pass;
            source = `pass: <hidden>`;
        } else {
            throw new Error('No secret provided');
        }

        if (!secret || typeof secret !== 'string') {
            throw new Error(`Secret (${source}) is not present, empty or not a string`);
        }

        const okm = hkdfSync(
            'sha512',
            secret, // IKM
            Buffer.from(this.config.url), // salt
            'Product: misskey\r\nSecret-Type: external-ikm\r\n', // info
            this.KEY_LENGTH,
        );

        const okmBuffer = Buffer.from(okm);

        // pad XOR
        for (let i = 0; i < this.KEY_LENGTH; i++) {
            this.persistentSecret[i] = this.persistentSecret[i] ^ okmBuffer[i];
        }
    }

    /**
     * Get a runtime secret for a given module and ID
     * @param module - The module name
     * @param id - The ID of the secret for private use in the module
     * @param length - The length of the secret to generate
     * @returns The runtime secret
     */
    public getRuntimeSecret(module: string, id: string, length: number = this.KEY_LENGTH): Buffer {
        if (!this.persistentSecret) {
            throw new Error('Runtime secret service not initialized');
        }

        const okm = hkdfSync(
            'sha512',
            this.persistentSecret, // IKM
            Buffer.from(this.config.url), // salt
            `Product: misskey\r\nSecret-Type: runtime-secret\r\nModule: ${module}\r\nID: ${id}\r\n`, // info
            length,
        );

        return Buffer.from(okm);
    }

    /**
     * Zeroize the persistent secret
     */
    public zeroize() {
        if (!this.persistentSecret) {
            return;
        }

        crypto.getRandomValues(this.persistentSecret);
        this.persistentSecret = null;

        if (globalThis.gc) {
            globalThis.gc();
        }
    }
}