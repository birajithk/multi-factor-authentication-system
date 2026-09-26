import crypto from "crypto";
import pool from "../config/database.js";


export async function createPendingAuth(userId) {
    const transactionId = crypto.randomUUID();

    const query = `
        INSERT INTO pending_auth (
            transaction_id,
            user_id,
            expires_at,
            failed_attempts
        )
        VALUES ($1, $2, NOW() + INTERVAL '5 minutes', 0)
        RETURNING
            transaction_id,
            user_id,
            expires_at,
            failed_attempts,
            created_at
    `;

    const result = await pool.query(query, [
        transactionId,
        userId
    ]);

    return result.rows[0];
}

export async function getPendingAuth(transactionId) {
    const query = `
        SELECT
            transaction_id,
            user_id,
            expires_at,
            failed_attempts,
            created_at
        FROM pending_auth
        WHERE transaction_id = $1
    `;

    const result = await pool.query(query, [transactionId]);

    return result.rows[0] ?? null;
}

export async function incrementPendingAuthFailures(transactionId) {
    const query = `
        UPDATE pending_auth
        SET failed_attempts = failed_attempts + 1
        WHERE transaction_id = $1
        RETURNING
            transaction_id,
            user_id,
            expires_at,
            failed_attempts
    `;

    const result = await pool.query(query, [transactionId]);

    return result.rows[0] ?? null;
}

export async function deletePendingAuth(transactionId) {
    const query = `
        DELETE FROM pending_auth
        WHERE transaction_id = $1
    `;

    await pool.query(query, [transactionId]);
}
