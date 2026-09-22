import pool from "../config/database.js";
import {
  createPasswordSecurityEvent,
} from "./password-event-metadata.service.js";
import { findUserByUsername } from "./user.service.js";

import {
  verifyPassword,
  performDummyPasswordVerification,
} from "./password.service.js";

import {
  buildPasswordRetryKey,
  lockPasswordAttemptKey,
  getPasswordAttemptStatus,
  recordPasswordFailure,
} from "./password-attempt.service.js";

/**
 * Generic result used for:
 * - unknown username
 * - incorrect password
 * - disabled account
 *
 * Public callers must not be able to distinguish these cases.
 */
function authenticationFailure({
  correlationId,
  userId = null,
}) {
  return {
    success: false,
    type: "AUTHENTICATION_FAILED",
    message: "Invalid username or password.",

    securityEvent: createPasswordSecurityEvent({
      eventType: "PASSWORD_AUTHENTICATION_FAILURE",
      outcome: "FAILURE",
      correlationId,
      userId,
    }),
  };
}

/**
 * Result returned when the rolling password-failure
 * budget has already been exhausted.
 */
function temporaryRestriction({
  retryAfterSeconds,
  correlationId,
  userId = null,
}) {
  return {
    success: false,
    type: "TEMPORARILY_RESTRICTED",
    message:
      "Too many failed authentication attempts. Try again later.",
    retry_after_seconds: retryAfterSeconds,

    securityEvent: createPasswordSecurityEvent({
      eventType: "TEMPORARY_RESTRICTION",
      outcome: "BLOCKED",
      correlationId,
      userId,
    }),
  };
}

/**
 * Verify the password first factor.
 *
 * IMPORTANT:
 * Password success does NOT mean MFA is complete.
 *
 * A successful result only proves the password for one
 * server-side account. The authentication controller decides
 * what restricted operation is permitted next.
 */
export async function verifyFirstFactor({
  username,
  password,
  correlationId,
}) {
  const suppliedPassword =
    typeof password === "string" ? password : "";

  // Find the account using the shared normalized username rule.
  const user = await findUserByUsername(username);

  // Existing accounts use user_id for retry tracking.
  // Unknown usernames use a SHA-256-derived retry key.
  const retryKey = buildPasswordRetryKey({
    user,
    username,
  });

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /*
     * Only one password-attempt transaction for this retry key
     * can perform the limit check/update at a time.
     */
    await lockPasswordAttemptKey(
      client,
      retryKey,
    );

    // -------------------------------------------------------
    // 1. Check the rolling 15-minute failure budget BEFORE
    // performing another password verification.
    // -------------------------------------------------------

    const attemptStatus =
      await getPasswordAttemptStatus(
        client,
        retryKey,
      );

    if (!attemptStatus.allowed) {
      await client.query("COMMIT");

      return temporaryRestriction({
      retryAfterSeconds:
          attemptStatus.retryAfterSeconds,

      correlationId,

      userId: user?.user_id ?? null,
      });
    }

    // -------------------------------------------------------
    // 2. Unknown account
    //
    // Perform dummy Argon2 verification so an unknown username
    // does not immediately take the cheap path.
    // -------------------------------------------------------

    if (!user) {
      await performDummyPasswordVerification(
        suppliedPassword,
      );

      await recordPasswordFailure(
        client,
        {
          retryKey,
          userId: null,
        },
      );

      await client.query("COMMIT");

      return authenticationFailure({
        correlationId,
        userId: null,
});
    }

    // -------------------------------------------------------
    // 3. Verify password
    // -------------------------------------------------------

    const passwordMatches =
      await verifyPassword(
        user.password_hash,
        suppliedPassword,
      );

    if (!passwordMatches) {
      await recordPasswordFailure(
        client,
        {
          retryKey,
          userId: user.user_id,
        },
      );

      await client.query("COMMIT");

      return authenticationFailure({
        correlationId,
        userId: user.user_id,
      });
    }

    // -------------------------------------------------------
    // 4. Disabled account
    //
    // Public response stays generic.
    //
    // We also record this as an unsuccessful authentication
    // attempt, matching the project's documented first-factor
    // failure flow.
    // -------------------------------------------------------

    if (user.account_status === "DISABLED") {
      await recordPasswordFailure(
        client,
        {
          retryKey,
          userId: user.user_id,
        },
      );

      await client.query("COMMIT");

      return authenticationFailure({
        correlationId,
        userId: user.user_id,
    });
    }

    // -------------------------------------------------------
    // 5. Password verified successfully
    //
    // Existing failures are NOT deleted here. The project rule
    // is a rolling failure window; successful verification does
    // not erase failures that occurred inside that window.
    // -------------------------------------------------------

    await client.query("COMMIT");

    return {
    success: true,
    type: "PASSWORD_VERIFIED",

    account: {
        user_id: user.user_id,
        username: user.username,
        account_status: user.account_status,
    },

    securityEvent: createPasswordSecurityEvent({
        eventType: "PASSWORD_AUTHENTICATION_SUCCESS",
        outcome: "SUCCESS",
        correlationId,
        userId: user.user_id,
    }),
    };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}