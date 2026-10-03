import { randomUUID } from "node:crypto";

import {
  createTOTPSecret,
  generateTOTPURI,
  verifyTOTPCode,
} from "../services/totp.service.js";

import {
  encryptSecret,
  decryptSecret,
} from "../services/encryption.service.js";

import {
  upsertUnverifiedTOTPRecord,
  getTOTPRecord,
  completeTOTPEnrollment,
} from "../services/totp.repository.js";

import {
  PENDING_COOKIE_NAME,
  PENDING_SCOPES,
  findPendingTransaction,
  deletePendingTransaction,
  clearPendingCookie,
  setSessionCookie,
} from "../services/session.service.js";

import {
  completeTOTPLogin,
} from "../services/totp-login.service.js";

import {
  createSessionSecurityEvent,
} from "../services/session-event-metadata.service.js";

import {
  SecurityLogger,
} from "../services/security-logger.service.js";

/**
 * Load the ENROLLMENT pending transaction from its HttpOnly
 * cookie.
 *
 * This is the ONLY accepted identity for enrollment. Headers,
 * body fields, MFA_PENDING tokens, and full sessions are not
 * accepted, and the account must still be ENROLLING.
 */
async function loadEnrollmentTransaction(req) {
  const pending = await findPendingTransaction(
    req.cookies?.[PENDING_COOKIE_NAME],
    PENDING_SCOPES.ENROLLMENT,
  );

  if (
    !pending ||
    pending.account_status !== "ENROLLING"
  ) {
    return null;
  }

  return pending;
}

function enrollmentAuthenticationRequired(res) {
  return res.status(401).json({
    success: false,
    error: {
      type: "AUTHENTICATION_REQUIRED",
      message:
        "Enrollment session is missing or expired. Sign in again.",
    },
  });
}

/**
 * Start TOTP enrollment.
 *
 * Requires the ENROLLMENT pending cookie created by
 * registration or by password login of an ENROLLING account.
 */
export async function startTOTPEnrollment(req, res) {
  try {
    const pending =
      await loadEnrollmentTransaction(req);

    if (!pending) {
      return enrollmentAuthenticationRequired(res);
    }

    const userId = pending.user_id;

    // Generate a new 160-bit TOTP secret.
    const secret = createTOTPSecret();

    // Encrypt the secret before storing it.
    const encrypted = encryptSecret(secret);

    /*
     * Store encrypted secret in PostgreSQL.
     *
     * An unverified credential from an interrupted enrollment
     * is replaced. A verified credential is never replaced.
     */
    const stored = await upsertUnverifiedTOTPRecord({
      userId,
      encryptedSecret: encrypted.encryptedSecret,
      nonce: encrypted.nonce,
      authTag: encrypted.authTag,
      keyId: encrypted.keyId,
    });

    if (!stored) {
      return res.status(409).json({
        error:
          "TOTP is already configured for this user.",
      });
    }

    // Generate authenticator-compatible URI.
    // The label is the username, not the internal user_id.
    const otpAuthUri = generateTOTPURI(
      secret,
      pending.username,
      "SecureByte",
    );

    /*
     * The setup secret is returned only during enrollment.
     *
     * IMPORTANT:
     * This plaintext secret should NOT be logged or stored
     * anywhere else.
     */
    return res.status(201).json({
      message: "TOTP enrollment started.",
      setupKey: secret,
      otpAuthUri,
    });
  } catch (error) {
    console.error(
      "TOTP enrollment error:",
      error,
    );

    return res.status(500).json({
      error: "Unable to start TOTP enrollment.",
    });
  }
}

/**
 * Verify the TOTP code submitted during enrollment.
 *
 * Success activates the account but does NOT create a full
 * session. The user must then sign in normally
 * (password + TOTP).
 */
export async function verifyTOTPEnrollment(
  req,
  res,
) {
  try {
    const { token } = req.body ?? {};

    const pending =
      await loadEnrollmentTransaction(req);

    if (!pending) {
      return enrollmentAuthenticationRequired(res);
    }

    const userId = pending.user_id;

    if (
      typeof token !== "string" ||
      !/^\d{6}$/.test(token)
    ) {
      return res.status(400).json({
        error:
          "TOTP code must be exactly 6 digits.",
      });
    }

    // Retrieve encrypted credential.
    const credential =
      await getTOTPRecord(userId);

    if (!credential) {
      return res.status(404).json({
        error:
          "TOTP enrollment was not started.",
      });
    }

    // Decrypt the server-side TOTP secret.
    const secret = decryptSecret(
      credential.encrypted_secret,
      credential.nonce,
      credential.auth_tag,
    );

    // Verify the submitted code.
    const verification =
      await verifyTOTPCode(
        secret,
        token,
      );

    if (!verification.valid) {
      return res.status(401).json({
        error: "Invalid TOTP code.",
      });
    }

    /*
     * Use the exact time-step the code matched
     * (otplib VerifyResult.timeStep), not the current server
     * step. Otherwise a code that matched the NEXT step
     * (client clock ahead) could be replayed at login.
     */
    const matchedStep = verification.timeStep;

    /*
     * Atomically:
     *
     * - check replay state
     * - update last_accepted_step
     * - activate the account
     */
    const result =
      await completeTOTPEnrollment(
        userId,
        matchedStep,
      );

    if (!result.success) {
      if (
        result.reason === "TOTP_REPLAY"
      ) {
        return res.status(409).json({
          error:
            "This TOTP time-step has already been used.",
        });
      }

      return res.status(400).json({
        error:
          "Unable to complete TOTP enrollment.",
      });
    }

    /*
     * Enrollment is finished, so the enrollment scope ends.
     * No full session is created here.
     */
    await deletePendingTransaction(
      pending.transaction_id,
    );

    clearPendingCookie(res);

    return res.status(200).json({
      message:
        "TOTP enrollment completed successfully.",
      user: result.user,
    });
  } catch (error) {
    console.error(
      "TOTP enrollment verification error:",
      error,
    );

    return res.status(500).json({
      error:
        "Unable to verify TOTP enrollment.",
    });
  }
}

/**
 * Hand one TOTP-login security event to the common logger.
 *
 * Never add TOTP codes, setup keys, or session tokens to the
 * event.
 */
async function recordTOTPSecurityEvent(
  securityEvent,
) {
  await SecurityLogger.logEvent({
    event_type: securityEvent.eventType,
    outcome: securityEvent.outcome,
    correlation_id:
      securityEvent.correlationId,
    user_id: securityEvent.userId,
  });
}

/**
 * POST /api/auth/totp
 *
 * Second factor of normal login.
 *
 * The account comes ONLY from the MFA_PENDING cookie created by
 * password verification. Any user_id or username in the body is
 * ignored.
 *
 * The full session cookie is set only after the database
 * transaction has committed.
 */
export async function verifyTOTPLogin(req, res) {
  const { token } = req.body ?? {};
  const correlationId = randomUUID();

  try {
    if (
      typeof token !== "string" ||
      !/^\d{6}$/.test(token)
    ) {
      return res.status(400).json({
        success: false,
        error: {
          type: "VALIDATION_ERROR",
          field: "token",
          message:
            "Verification code must be exactly 6 digits.",
        },
      });
    }

    const result = await completeTOTPLogin({
      pendingToken:
        req.cookies?.[PENDING_COOKIE_NAME],
      token,
    });

    if (!result.success) {
      /*
       * Account-level rolling second-factor restriction.
       */
      if (
        result.type ===
        "TEMPORARILY_RESTRICTED"
      ) {
        await recordTOTPSecurityEvent(
          createSessionSecurityEvent({
            eventType:
              "TEMPORARY_RESTRICTION",
            outcome: "BLOCKED",
            correlationId,
            userId: result.userId,
          }),
        );

        res.set(
          "Retry-After",
          String(result.retryAfterSeconds),
        );

        return res.status(429).json({
          success: false,
          error: {
            type:
              "TEMPORARILY_RESTRICTED",
            message:
              "Too many failed verification attempts. Try again later.",
            retry_after_seconds:
              result.retryAfterSeconds,
          },
        });
      }

      /*
       * Log the failed second-factor verification.
       *
       * The event contains metadata only. The submitted
       * TOTP code is never logged.
       */
      await recordTOTPSecurityEvent(
        createSessionSecurityEvent({
          eventType:
            "TOTP_VERIFICATION_FAILURE",
          outcome: "FAILURE",
          correlationId,
          userId: result.userId,
        }),
      );

      if (
        result.type === "INVALID_CODE"
      ) {
        // Fifth failure ended this pending transaction.
        if (result.transactionEnded) {
          clearPendingCookie(res);
        }

        return res.status(401).json({
          success: false,
          error: {
            type:
              "AUTHENTICATION_FAILED",
            message:
              "Invalid verification code.",
          },
        });
      }

      /*
       * Missing, expired, used-up, or wrong-scope pending
       * transaction, or the account is no longer ACTIVE.
       */
      clearPendingCookie(res);

      return res.status(401).json({
        success: false,
        error: {
          type:
            "AUTHENTICATION_REQUIRED",
          message:
            "Sign-in session is missing or expired. Sign in again.",
        },
      });
    }

    /*
     * TOTP successfully completed.
     *
     * The code itself and the session token are deliberately
     * excluded from the security event.
     */
    await recordTOTPSecurityEvent(
      createSessionSecurityEvent({
        eventType:
          "TOTP_VERIFICATION_SUCCESS",
        outcome: "SUCCESS",
        correlationId,
        userId: result.userId,
      }),
    );

    /*
     * The database transaction has committed.
     * It is now safe to issue the full session cookie.
     */
    setSessionCookie(
      res,
      result.sessionToken,
    );

    clearPendingCookie(res);

    return res.status(200).json({
      success: true,
      result: "AUTHENTICATED",
      next_step: "DASHBOARD",
    });
  } catch (error) {
    console.error(
      "TOTP login verification failed:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "Verification could not be completed.",
      },
    });
  }
}