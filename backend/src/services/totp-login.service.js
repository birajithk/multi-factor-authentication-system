import pool from "../config/database.js";
import { decryptSecret } from "./encryption.service.js";
import { verifyTOTPCode } from "./totp.service.js";

import {
  PENDING_SCOPES,
  hashToken,
  isWellFormedToken,
  insertFullSession,
} from "./session.service.js";

import {
  lockSecondFactorAccount,
  getSecondFactorAttemptStatus,
  recordSecondFactorFailure,
} from "./second-factor-attempt.service.js";

// Wrong codes allowed on ONE pending transaction.
export const PENDING_FAILURE_LIMIT = 5;

function pendingInvalid(userId = null) {
  return {
    success: false,
    type: "PENDING_INVALID",
    userId,
  };
}

/**
 * Delete a pending transaction inside the current transaction.
 */
async function deletePending(client, transactionId) {
  await client.query(
    `
      DELETE FROM pending_auth
      WHERE transaction_id = $1
    `,
    [transactionId],
  );
}

/**
 * Complete login with the TOTP second factor.
 *
 * The account comes ONLY from the MFA_PENDING transaction that
 * matches the pending cookie. Nothing in the request body can
 * choose or change the account.
 *
 * Everything below runs in ONE PostgreSQL transaction:
 *
 * 1. lock the pending row (FOR UPDATE),
 * 2. serialize second-factor attempts for the account,
 * 3. require an ACTIVE account and an available failure budget,
 * 4. lock the TOTP credential row (FOR UPDATE),
 * 5. verify the code and require matched step > last accepted
 *    step (replay protection),
 * 6. on success: update last_accepted_step, delete the pending
 *    row, insert the full session, then COMMIT.
 *
 * The caller sets cookies only after this function returns,
 * which is after COMMIT.
 */
export async function completeTOTPLogin({
  pendingToken,
  token,
}) {
  if (!isWellFormedToken(pendingToken)) {
    return pendingInvalid();
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // -------------------------------------------------------
    // 1. Pending MFA transaction (cookie only)
    // -------------------------------------------------------

    const pendingResult = await client.query(
      `
        SELECT
          transaction_id,
          user_id,
          failed_attempts,
          expires_at > NOW() AS is_live
        FROM pending_auth
        WHERE token_hash = $1
          AND scope = $2
        FOR UPDATE
      `,
      [
        hashToken(pendingToken),
        PENDING_SCOPES.MFA_PENDING,
      ],
    );

    const pending = pendingResult.rows[0];

    if (!pending) {
      await client.query("COMMIT");
      return pendingInvalid();
    }

    const userId = pending.user_id;

    if (
      !pending.is_live ||
      pending.failed_attempts >= PENDING_FAILURE_LIMIT
    ) {
      await deletePending(client, pending.transaction_id);
      await client.query("COMMIT");
      return pendingInvalid(userId);
    }

    // -------------------------------------------------------
    // 2. One second-factor attempt per account at a time
    // -------------------------------------------------------

    await lockSecondFactorAccount(client, userId);

    // -------------------------------------------------------
    // 3. Account state and rolling account budget
    // -------------------------------------------------------

    const userResult = await client.query(
      `
        SELECT account_status
        FROM users
        WHERE user_id = $1
      `,
      [userId],
    );

    if (userResult.rows[0]?.account_status !== "ACTIVE") {
      await deletePending(client, pending.transaction_id);
      await client.query("COMMIT");
      return pendingInvalid(userId);
    }

    const attemptStatus =
      await getSecondFactorAttemptStatus(client, userId);

    if (!attemptStatus.allowed) {
      await client.query("COMMIT");

      return {
        success: false,
        type: "TEMPORARILY_RESTRICTED",
        retryAfterSeconds: attemptStatus.retryAfterSeconds,
        userId,
      };
    }

    // -------------------------------------------------------
    // 4. TOTP credential
    // -------------------------------------------------------

    const credentialResult = await client.query(
      `
        SELECT
          encrypted_secret,
          nonce,
          auth_tag,
          last_accepted_step
        FROM totp_credentials
        WHERE user_id = $1
        FOR UPDATE
      `,
      [userId],
    );

    const credential = credentialResult.rows[0];

    if (!credential) {
      await deletePending(client, pending.transaction_id);
      await client.query("COMMIT");
      return pendingInvalid(userId);
    }

    // -------------------------------------------------------
    // 5. Verify code and replay state
    // -------------------------------------------------------

    const secret = decryptSecret(
      credential.encrypted_secret,
      credential.nonce,
      credential.auth_tag,
    );

    const verification = await verifyTOTPCode(
      secret,
      token,
    );

    const lastAcceptedStep =
      credential.last_accepted_step === null
        ? null
        : Number(credential.last_accepted_step);

    // verification.timeStep is the exact step the code matched.
    const accepted =
      verification.valid &&
      (
        lastAcceptedStep === null ||
        verification.timeStep > lastAcceptedStep
      );

    if (!accepted) {
      const failureResult = await client.query(
        `
          UPDATE pending_auth
          SET failed_attempts = failed_attempts + 1
          WHERE transaction_id = $1
          RETURNING failed_attempts
        `,
        [pending.transaction_id],
      );

      await recordSecondFactorFailure(client, userId);

      const transactionEnded =
        failureResult.rows[0].failed_attempts >=
        PENDING_FAILURE_LIMIT;

      if (transactionEnded) {
        await deletePending(client, pending.transaction_id);
      }

      await client.query("COMMIT");

      return {
        success: false,
        type: "INVALID_CODE",
        transactionEnded,
        userId,
      };
    }

    // -------------------------------------------------------
    // 6. Success: record step, end pending, create session
    // -------------------------------------------------------

    await client.query(
      `
        UPDATE totp_credentials
        SET
          last_accepted_step = $2,
          updated_at = NOW()
        WHERE user_id = $1
      `,
      [userId, verification.timeStep],
    );

    await deletePending(client, pending.transaction_id);

    const sessionToken = await insertFullSession(
      client,
      userId,
    );

    await client.query("COMMIT");

    return {
      success: true,
      sessionToken,
      userId,
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
