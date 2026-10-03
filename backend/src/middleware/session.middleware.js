import {
  SESSION_COOKIE_NAME,
  PENDING_COOKIE_NAME,
  PENDING_SCOPES,
  findActiveSession,
  findPendingTransaction,
} from "../services/session.service.js";

import {
  RecoveryService,
  RECOVERY_COOKIE_NAME,
} from "../services/recovery.service.js";

/**
 * Protected-resource guard.
 *
 * Only a full session (password + TOTP completed) passes.
 * The session is loaded from the database on EVERY request.
 */
export async function requireFullSession(req, res, next) {
  try {
    const token =
      req.cookies?.[SESSION_COOKIE_NAME];

    const session =
      await findActiveSession(token);

    if (!session) {
      return res.status(401).json({
        success: false,
        error: {
          type: "AUTHENTICATION_REQUIRED",
          message:
            "Authentication is required.",
        },
      });
    }

    /*
     * Server-controlled identity.
     *
     * Never take the authenticated user from request headers
     * or the request body.
     */
    req.authSession = {
      sessionId: session.session_id,
      userId: session.user_id,
      username: session.username,
      createdAt: session.created_at,
      expiresAt: session.expires_at,
    };

    return next();
  } catch (error) {
    console.error(
      "Session verification failed:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "The request could not be completed.",
      },
    });
  }
}

/**
 * Backwards-compatible name used by existing routes.
 */
export const requireFullAuth =
  requireFullSession;

/**
 * Require a password-verified MFA_PENDING transaction.
 *
 * Used when the user has passed factor 1 but has not yet
 * completed factor 2.
 *
 * The account identity comes only from the HttpOnly
 * securebyte_pending cookie.
 */
export async function requireMfaPending(
  req,
  res,
  next,
) {
  try {
    const token =
      req.cookies?.[PENDING_COOKIE_NAME];

    const pending =
      await findPendingTransaction(
        token,
        PENDING_SCOPES.MFA_PENDING,
      );

    if (!pending) {
      return res.status(401).json({
        success: false,
        error: {
          type: "AUTHENTICATION_REQUIRED",
          message:
            "Sign-in session is missing or expired. Sign in again.",
        },
      });
    }

    /*
     * Keep pending identity separate from full-session identity.
     */
    req.pendingAuth = {
      transactionId:
        pending.transaction_id,
      userId: pending.user_id,
      username: pending.username,
      scope: pending.scope,
      failedAttempts:
        pending.failed_attempts,
      expiresAt: pending.expires_at,
    };

    return next();
  } catch (error) {
    console.error(
      "Pending authentication verification failed:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "The request could not be completed.",
      },
    });
  }
}

/**
 * Temporary compatibility alias.
 *
 * Existing code importing requirePendingAuth will now receive
 * the secure cookie-backed MFA_PENDING validation rather than
 * trusting x-pending-auth-id.
 *
 * New code should prefer requireMfaPending.
 */
export const requirePendingAuth =
  requireMfaPending;

/**
 * Simple CSRF defense for cookie-authenticated state changes.
 */
export async function requireRecoverySession(
  req,
  res,
  next,
) {
  try {
    const token =
      req.cookies?.[RECOVERY_COOKIE_NAME];

    const recoverySession =
      await RecoveryService.findActiveRecoverySession(
        token,
      );

    if (!recoverySession) {
      return res.status(401).json({
        success: false,
        error: {
          type: "AUTHENTICATION_REQUIRED",
          message:
            "Recovery session is missing or expired.",
        },
      });
    }

    req.recoverySession = {
      userId:
        recoverySession.user_id,
      username:
        recoverySession.username,
      scope:
        recoverySession.scope,
      expiresAt:
        recoverySession.expiry,
      extensionCount:
        recoverySession.extension_count,
    };

    return next();
  } catch (error) {
    console.error(
      "Recovery session verification failed:",
      error.message,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "The request could not be completed.",
      },
    });
  }
}


export function requireJsonRequest(
  req,
  res,
  next,
) {
  const contentType =
    (req.get("content-type") ?? "")
      .split(";")[0]
      .trim()
      .toLowerCase();

  if (
    contentType !== "application/json"
  ) {
    return res.status(415).json({
      success: false,
      error: {
        type:
          "UNSUPPORTED_CONTENT_TYPE",
        message:
          "Content-Type must be application/json.",
      },
    });
  }

  return next();
}