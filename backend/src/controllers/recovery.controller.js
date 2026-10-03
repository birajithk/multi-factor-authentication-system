import {
  RecoveryService,
  RECOVERY_COOKIE_NAME,
  RECOVERY_SESSION_LIFETIME_MINUTES,
} from "../services/recovery.service.js";

import {
  consumeSourceAuthenticationSubmission,
} from "../services/source-rate-limit.service.js";

import {
  clearPendingCookie,
} from "../services/session.service.js";

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
  completeTOTPRecoveryEnrollment,
} from "../services/totp.repository.js";

import {
  SecurityLogger,
} from "../services/security-logger.service.js";

function recoveryCookieOptions() {
  return {
    httpOnly: true,
    secure:
      process.env.COOKIE_SECURE !== "false",
    sameSite: "lax",
    path: "/",
    maxAge:
      RECOVERY_SESSION_LIFETIME_MINUTES *
      60 *
      1000,
  };
}

function clearRecoveryCookie(res) {
  res.clearCookie(
    RECOVERY_COOKIE_NAME,
    {
      httpOnly: true,
      secure:
        process.env.COOKIE_SECURE !==
        "false",
      sameSite: "lax",
      path: "/",
    },
  );
}

/**
 * POST /api/recovery/generate
 *
 * Requires a FULL authenticated session.
 */
export async function generateCodes(
  req,
  res,
) {
  try {
    const sourceStatus =
      await consumeSourceAuthenticationSubmission(
        req.ip,
      );

    if (!sourceStatus.allowed) {
      res.set(
        "Retry-After",
        String(
          sourceStatus.retryAfterSeconds,
        ),
      );

      return res.status(429).json({
        success: false,
        error: {
          type:
            "TEMPORARILY_RESTRICTED",
          message:
            "Too many authentication attempts. Try again later.",
          retry_after_seconds:
            sourceStatus.retryAfterSeconds,
        },
      });
    }

    /*
     * requireFullAuth supplies req.authSession.
     */
    const userId =
      req.authSession?.userId;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          type:
            "AUTHENTICATION_REQUIRED",
          message:
            "Authentication is required.",
        },
      });
    }

    const codes =
      await RecoveryService.generateRecoveryCodes(
        userId,
      );

    return res.status(200).json({
      success: true,
      data: {
        recoveryCodes: codes,
      },
    });
  } catch (error) {
    console.error(
      "Error generating recovery codes:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "Recovery codes could not be generated.",
      },
    });
  }
}

/**
 * POST /api/recovery/consume
 *
 * Password factor must already have succeeded.
 *
 * requireMfaPending supplies req.pendingAuth using the
 * securebyte_pending HttpOnly cookie.
 */
export async function consumeCode(
  req,
  res,
) {
  try {
    const sourceStatus =
      await consumeSourceAuthenticationSubmission(
        req.ip,
      );

    if (!sourceStatus.allowed) {
      res.set(
        "Retry-After",
        String(
          sourceStatus.retryAfterSeconds,
        ),
      );

      return res.status(429).json({
        success: false,
        error: {
          type:
            "TEMPORARILY_RESTRICTED",
          message:
            "Too many authentication attempts. Try again later.",
          retry_after_seconds:
            sourceStatus.retryAfterSeconds,
        },
      });
    }

    const { recoveryCode } =
      req.body ?? {};

    /*
     * Never trust user identity from the body.
     * It comes only from the MFA_PENDING transaction.
     */
    const userId =
      req.pendingAuth?.userId;

    if (!userId) {
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

    if (
      typeof recoveryCode !== "string" ||
      recoveryCode.trim().length === 0
    ) {
      return res.status(400).json({
        success: false,
        error: {
          type: "VALIDATION_ERROR",
          field: "recoveryCode",
          message:
            "Recovery code is required.",
        },
      });
    }

    const result =
      await RecoveryService.consumeRecoveryCode(
        userId,
        recoveryCode,
      );

    if (!result.success) {
      if (
        result.type ===
        "TEMPORARILY_RESTRICTED"
      ) {
        res.set(
          "Retry-After",
          String(
            result.retryAfterSeconds,
          ),
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

      return res.status(401).json({
        success: false,
        error: {
          type:
            "AUTHENTICATION_FAILED",
          message:
            "Invalid or already used recovery code.",
        },
      });
    }

    /*
     * The old MFA_PENDING database transaction was consumed
     * inside the recovery transaction.
     *
     * Remove the corresponding browser cookie as well.
     */
    clearPendingCookie(res);

    /*
     * Browser gets only the RAW opaque recovery token.
     *
     * PostgreSQL contains only SHA-256(raw token).
     */
    res.cookie(
      RECOVERY_COOKIE_NAME,
      result.recoveryToken,
      recoveryCookieOptions(),
    );

    return res.status(200).json({
      success: true,
      result: "RECOVERY_AUTHORIZED",
      next_step:
        "AUTHENTICATOR_REPLACEMENT",
      message:
        "Recovery authorized. Configure a new authenticator.",
    });
  } catch (error) {
    console.error(
      "Error consuming recovery code:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "Recovery could not be completed.",
      },
    });
  }
}

/**
 * POST /api/recovery/totp/enroll
 *
 * Starts authenticator replacement.
 *
 * Requires a valid RECOVERY_ONLY session.
 */
export async function startRecoveryTOTPEnrollment(
  req,
  res,
) {
  try {
    const userId =
      req.recoverySession?.userId;

    const username =
      req.recoverySession?.username;

    if (!userId || !username) {
      return res.status(401).json({
        success: false,
        error: {
          type:
            "AUTHENTICATION_REQUIRED",
          message:
            "Recovery authorization is required.",
        },
      });
    }

    /*
     * Generate a completely new authenticator
     * secret. The previous credential was removed
     * when recovery was authorized.
     */
    const secret =
      createTOTPSecret();

    const encrypted =
      encryptSecret(secret);

    const stored =
      await upsertUnverifiedTOTPRecord({
        userId,
        encryptedSecret:
          encrypted.encryptedSecret,
        nonce: encrypted.nonce,
        authTag: encrypted.authTag,
        keyId: encrypted.keyId,
      });

    if (!stored) {
      return res.status(409).json({
        success: false,
        error: {
          type:
            "AUTHENTICATOR_ALREADY_CONFIGURED",
          message:
            "An authenticator is already configured.",
        },
      });
    }

    const otpAuthUri =
      generateTOTPURI(
        secret,
        username,
        "SecureByte",
      );

    /*
     * Plaintext setup key is returned only here.
     * Never log it.
     */
    return res.status(201).json({
      success: true,
      result:
        "RECOVERY_TOTP_ENROLLMENT_STARTED",
      setupKey: secret,
      otpAuthUri,
    });
  } catch (error) {
    console.error(
      "Recovery TOTP enrollment failed:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "Authenticator replacement could not be started.",
      },
    });
  }
}

/**
 * POST /api/recovery/totp/enroll/verify
 *
 * Verifies the replacement authenticator.
 *
 * Success:
 * RECOVERY_REQUIRED -> ACTIVE
 *
 * It does NOT create a full application session.
 */
export async function verifyRecoveryTOTPEnrollment(
  req,
  res,
) {
  try {
    const userId =
      req.recoverySession?.userId;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: {
          type:
            "AUTHENTICATION_REQUIRED",
          message:
            "Recovery authorization is required.",
        },
      });
    }

    const { token } = req.body ?? {};

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

    const credential =
      await getTOTPRecord(userId);

    if (!credential) {
      return res.status(404).json({
        success: false,
        error: {
          type:
            "AUTHENTICATOR_NOT_STARTED",
          message:
            "Authenticator replacement has not been started.",
        },
      });
    }

    const secret =
      decryptSecret(
        credential.encrypted_secret,
        credential.nonce,
        credential.auth_tag,
      );

    const verification =
      await verifyTOTPCode(
        secret,
        token,
      );

    if (!verification.valid) {
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
     * Store the exact TOTP step that matched.
     */
    const result =
      await completeTOTPRecoveryEnrollment(
        userId,
        verification.timeStep,
      );

    if (!result.success) {
      if (
        result.reason === "TOTP_REPLAY"
      ) {
        return res.status(409).json({
          success: false,
          error: {
            type: "TOTP_REPLAY",
            message:
              "This verification code has already been used.",
          },
        });
      }

      return res.status(400).json({
        success: false,
        error: {
          type:
            "RECOVERY_COMPLETION_FAILED",
          message:
            "Authenticator replacement could not be completed.",
        },
      });
    }

    /*
     * Audit the completed replacement.
     *
     * No TOTP secret/code/session token is logged.
     */
    await SecurityLogger.logEvent({
      event_type:
        "AUTHENTICATOR_REPLACEMENT",
      outcome: "SUCCESS",
      user_id: userId,
    });

    /*
     * Database recovery session was deleted inside
     * completeTOTPRecoveryEnrollment().
     *
     * Remove the browser credential too.
     */
    clearRecoveryCookie(res);

    return res.status(200).json({
      success: true,
      result:
        "AUTHENTICATOR_REPLACED",
      next_step: "NORMAL_LOGIN",
      user: result.user,
      message:
        "Authenticator replacement completed. Sign in normally with your password and new authenticator.",
    });
  } catch (error) {
    console.error(
      "Recovery TOTP verification failed:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "Authenticator replacement could not be completed.",
      },
    });
  }
}