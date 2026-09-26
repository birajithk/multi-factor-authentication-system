import db from "../config/database.js";
import {
  SESSION_COOKIE_NAME,
  findActiveSession,
} from "../services/session.service.js";

/**
 * Protected-resource guard.
 *
 * Only a full session (password + TOTP completed) passes.
 * The session is loaded from the database on EVERY request.
 *
 * - the cookie token hash must match a stored session,
 * - the session must not be revoked or expired,
 * - the account must still be ACTIVE.
 *
 * Pending (ENROLLMENT / MFA_PENDING) tokens use a different
 * cookie and a different table, so they can never pass.
 */
export async function requireFullSession(req, res, next) {
  try {
    const token = req.cookies?.[SESSION_COOKIE_NAME];

    const session = await findActiveSession(token);

    if (!session) {
      return res.status(401).json({
        success: false,
        error: {
          type: "AUTHENTICATION_REQUIRED",
          message: "Authentication is required.",
        },
      });
    }

    // Server-side identity for downstream handlers.
    // Never taken from request headers or body.
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
      error.message
    );

    // Fail closed.
    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message: "The request could not be completed.",
      },
    });
  }
}

/**
 * Backwards-compatible name for existing controllers/routes.
 *
 * Existing code using requireFullAuth will now receive the
 * secure cookie-backed full-session validation.
 */
export const requireFullAuth = requireFullSession;

/**
 * Pending authentication guard.
 *
 * Used only for flows that occur before full authentication,
 * such as MFA enrollment/verification.
 */
export const requirePendingAuth = async (req, res, next) => {
  try {
    const transactionId = req.headers["x-pending-auth-id"];

    if (
      typeof transactionId !== "string" ||
      transactionId.trim().length === 0
    ) {
      return res.status(401).json({
        success: false,
        error: {
          type: "UNAUTHORIZED",
        },
      });
    }

    const result = await db.query(
      `
        SELECT user_id
        FROM pending_auth
        WHERE transaction_id = $1
          AND expires_at > NOW()
      `,
      [transactionId.trim()]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        success: false,
        error: {
          type: "UNAUTHORIZED",
        },
      });
    }

    req.user = {
      user_id: result.rows[0].user_id,
    };

    return next();
  } catch (error) {
    console.error(
      "Error in requirePendingAuth middleware:",
      error.message
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
      },
    });
  }
};

/**
 * Simple CSRF defense for cookie-authenticated state changes.
 *
 * A cross-site HTML form can only send form/text content types.
 * Requiring application/json forces a browser CORS preflight,
 * which this API does not allow cross-origin.
 */
export function requireJsonRequest(req, res, next) {
  const contentType = (req.get("content-type") ?? "")
    .split(";")[0]
    .trim()
    .toLowerCase();

  if (contentType !== "application/json") {
    return res.status(415).json({
      success: false,
      error: {
        type: "UNSUPPORTED_CONTENT_TYPE",
        message: "Content-Type must be application/json.",
      },
    });
  }

  return next();
};