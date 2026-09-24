import {
  SESSION_COOKIE_NAME,
  findActiveSession,
} from "../services/session.service.js";

/**
 * Protected-resource guard.
 *
 * Only a full session (password + TOTP completed) passes.
 * The session is loaded from the database on EVERY request:
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
}
