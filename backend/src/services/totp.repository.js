import pool from "../config/database.js";

/**
 * Store an encrypted TOTP credential for a user.
 */
export async function createTOTPRecord({
    userId,
    encryptedSecret,
    nonce,
    authTag,
    keyId
}) {
    const query = `
        INSERT INTO totp_credentials (
            user_id,
            encrypted_secret,
            nonce,
            auth_tag,
            key_id,
            last_accepted_step
        )
        VALUES ($1, $2, $3, $4, $5, NULL)
        RETURNING
            user_id,
            key_id,
            last_accepted_step,
            created_at,
            updated_at
    `;

    const values = [
        userId,
        encryptedSecret,
        nonce,
        authTag,
        keyId
    ];

    const result = await pool.query(query, values);

    return result.rows[0];
}

/**
 * Store an encrypted TOTP credential, replacing one that has
 * never been verified.
 *
 * This lets an interrupted enrollment restart with a fresh
 * secret after the user signs in again. A credential that has
 * already accepted a code (last_accepted_step IS NOT NULL) is
 * never replaced.
 *
 * Returns null when a verified credential already exists.
 */
export async function upsertUnverifiedTOTPRecord({
    userId,
    encryptedSecret,
    nonce,
    authTag,
    keyId
}) {
    const query = `
        INSERT INTO totp_credentials (
            user_id,
            encrypted_secret,
            nonce,
            auth_tag,
            key_id,
            last_accepted_step
        )
        VALUES ($1, $2, $3, $4, $5, NULL)
        ON CONFLICT (user_id) DO UPDATE
        SET
            encrypted_secret = EXCLUDED.encrypted_secret,
            nonce = EXCLUDED.nonce,
            auth_tag = EXCLUDED.auth_tag,
            key_id = EXCLUDED.key_id,
            updated_at = NOW()
        WHERE totp_credentials.last_accepted_step IS NULL
        RETURNING
            user_id,
            key_id,
            last_accepted_step,
            created_at,
            updated_at
    `;

    const values = [
        userId,
        encryptedSecret,
        nonce,
        authTag,
        keyId
    ];

    const result = await pool.query(query, values);

    return result.rows[0] ?? null;
}

/**
 * Retrieve an encrypted TOTP credential.
 */
export async function getTOTPRecord(userId) {
    const query = `
        SELECT
            user_id,
            encrypted_secret,
            nonce,
            auth_tag,
            key_id,
            last_accepted_step,
            created_at,
            updated_at
        FROM totp_credentials
        WHERE user_id = $1
    `;

    const result = await pool.query(query, [userId]);

    return result.rows[0] ?? null;
}

/**
 * Atomically complete TOTP enrollment.
 *
 * This transaction:
 *
 * 1. Locks the TOTP credential row.
 * 2. Checks that the time-step has not already been accepted.
 * 3. Updates last_accepted_step.
 * 4. Activates the user account.
 *
 * The row lock prevents two simultaneous requests from
 * accepting the same time-step.
 */
export async function completeTOTPEnrollment(
    userId,
    timeStep
) {
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const credentialResult = await client.query(
            `
            SELECT
                user_id,
                last_accepted_step
            FROM totp_credentials
            WHERE user_id = $1
            FOR UPDATE
            `,
            [userId]
        );

        if (credentialResult.rows.length === 0) {
            throw new Error(
                "TOTP credential not found."
            );
        }

        const credential = credentialResult.rows[0];

        /*
         * Replay protection.
         *
         * The accepted time-step must always move forward.
         */
        if (
            credential.last_accepted_step !== null &&
            timeStep <= Number(
                credential.last_accepted_step
            )
        ) {
            await client.query("ROLLBACK");

            return {
                success: false,
                reason: "TOTP_REPLAY"
            };
        }

        /*
         * Record the newly accepted time-step.
         */
        await client.query(
            `
            UPDATE totp_credentials
            SET
                last_accepted_step = $2,
                updated_at = NOW()
            WHERE user_id = $1
            `,
            [userId, timeStep]
        );

        /*
         * Activate the account only after successful
         * TOTP verification.
         */
        const userResult = await client.query(
            `
            UPDATE users
            SET account_status = 'ACTIVE'
            WHERE user_id = $1
              AND account_status = 'ENROLLING'
            RETURNING
                user_id,
                username,
                account_status
            `,
            [userId]
        );

        if (userResult.rows.length === 0) {
            throw new Error(
                "User is not in ENROLLING state."
            );
        }

        await client.query("COMMIT");

        return {
            success: true,
            user: userResult.rows[0]
        };

    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}