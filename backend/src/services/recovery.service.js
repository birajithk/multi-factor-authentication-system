import crypto from 'crypto';
import db from '../config/database.js';
import { SecurityLogger } from './security-logger.service.js';

export class RecoveryService {
    /**
     * Generate 10 recovery codes for a user
     * @param {string} userId
     * @returns {Promise<string[]>} Array of plaintext recovery codes
     */
    static async generateRecoveryCodes(userId) {
        const plainCodes = [];
        const hashedCodes = [];

        // R4 Generate and hash the recovery set
        for (let i = 0; i < 10; i++) {
            // 128 random bits = 16 bytes -> 32 hex characters
            const code = crypto.randomBytes(16).toString('hex');
            
            // Format can have optional grouping, but we normalize it before hashing
            const normalizedCode = this.normalizeCode(code);
            const salt = crypto.randomBytes(16).toString('hex');
            
            const hash = crypto.createHash('sha256').update(normalizedCode + salt).digest('hex');
            
            plainCodes.push(code);
            hashedCodes.push({ code_id: crypto.randomUUID(), user_id: userId, salt, hash });
        }

        const client = await db.connect();
        try {
            await client.query('BEGIN');

            // R6 Apply replacement-set rules
            await client.query(`
                UPDATE recovery_codes 
                SET revoked_time = NOW() 
                WHERE user_id = $1 AND used_time IS NULL AND revoked_time IS NULL
            `, [userId]);

            // Store new codes
            for (const item of hashedCodes) {
                await client.query(`
                    INSERT INTO recovery_codes (code_id, user_id, salt, code_hash, issued_time)
                    VALUES ($1, $2, $3, $4, NOW())
                `, [item.code_id, item.user_id, item.salt, item.hash]);
            }

            await client.query('COMMIT');

            // Log recovery-code regeneration
            await SecurityLogger.logEvent({
                event_type: 'recovery_code_regeneration',
                outcome: 'success',
                user_id: userId
            });
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }

        // R5 Present the original values once
        return plainCodes;
    }

    /**
     * Normalize code (R3)
     * @param {string} code 
     * @returns {string}
     */
    static normalizeCode(code) {
        return code.replace(/[^a-fA-F0-9]/g, '').toLowerCase();
    }

    /**
     * Verify eligibility and consume a code atomically
     * @param {string} userId 
     * @param {string} submittedCode 
     */
    static async consumeRecoveryCode(userId, submittedCode) {
        const normalizedCode = this.normalizeCode(submittedCode);

        const client = await db.connect();
        try {
            await client.query('BEGIN');

            // Select unused and unrevoked codes for this user
            const result = await client.query(`
                SELECT code_id, salt, code_hash 
                FROM recovery_codes 
                WHERE user_id = $1 AND used_time IS NULL AND revoked_time IS NULL
            `, [userId]);

            let matchedCodeId = null;

            // R8 Verify eligibility before consuming a code
            for (const record of result.rows) {
                const computedHash = crypto.createHash('sha256').update(normalizedCode + record.salt).digest('hex');
                if (computedHash === record.code_hash) {
                    matchedCodeId = record.code_id;
                    break;
                }
            }

            if (!matchedCodeId) {
                await client.query('ROLLBACK');
                await SecurityLogger.logEvent({
                    event_type: 'recovery_code_use',
                    outcome: 'failure',
                    user_id: userId
                });
                return false; // Code invalid or used/revoked
            }

            // R9 Consume proof and restrict the account atomically
            // 1. Consume the code
            const consumeResult = await client.query(`
                UPDATE recovery_codes 
                SET used_time = NOW() 
                WHERE code_id = $1 AND used_time IS NULL AND revoked_time IS NULL
            `, [matchedCodeId]);

            if (consumeResult.rowCount === 0) {
                // Someone else consumed it concurrently
                await client.query('ROLLBACK');
                return false;
            }

            // 2. Set RECOVERY_REQUIRED
            await client.query(`
                UPDATE users 
                SET account_status = 'RECOVERY_REQUIRED' 
                WHERE user_id = $1
            `, [userId]);

            // 3. Revoke old authenticator (assuming we delete or invalidate in totp_credentials)
            await client.query(`
                DELETE FROM totp_credentials 
                WHERE user_id = $1
            `, [userId]);

            // 4. Invalidate existing sessions and pending login transactions
            await client.query(`
                UPDATE sessions 
                SET revoked_at = NOW() 
                WHERE user_id = $1 AND revoked_at IS NULL
            `, [userId]);

            await client.query(`
                DELETE FROM pending_auth 
                WHERE user_id = $1
            `, [userId]);

            // Create recovery-only session
            const identifierHash = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex');
            const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 mins for recovery
            
            await client.query(`
                INSERT INTO recovery_sessions (identifier_hash, user_id, scope, expiry)
                VALUES ($1, $2, 'recovery-only', $3)
            `, [identifierHash, userId, expiry]);

            await client.query('COMMIT');

            await SecurityLogger.logEvent({
                event_type: 'recovery_code_use',
                outcome: 'success',
                user_id: userId
            });

            return identifierHash;
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }
}
