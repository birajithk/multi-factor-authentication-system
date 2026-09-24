import { randomUUID } from "node:crypto";

import {
  revokeSession,
  clearSessionCookie,
} from "../services/session.service.js";

import {
  createSessionSecurityEvent,
} from "../services/session-event-metadata.service.js";

/*
 * Every handler in this file runs AFTER requireFullSession.
 *
 * req.authSession is loaded server-side from the session cookie.
 * User identity is never read from request headers or body.
 */

/**
 * GET /api/dashboard
 *
 * Demo protected resource. Reachable only with a full session
 * (password + TOTP).
 */
export function getDashboard(req, res) {
  return res.status(200).json({
    success: true,
    dashboard: {
      username: req.authSession.username,
      message: "Welcome to your SecureByte dashboard.",
    },
  });
}

/**
 * GET /api/session
 *
 * Current full-session information. Does not expose the
 * session token, its hash, or internal IDs.
 */
export function getCurrentSession(req, res) {
  return res.status(200).json({
    success: true,
    session: {
      username: req.authSession.username,
      account_status: "ACTIVE",
      created_at: req.authSession.createdAt,
      expires_at: req.authSession.expiresAt,
    },
  });
}

/**
 * POST /api/session/logout
 *
 * Revokes the current session server-side (revoked_at), so the
 * old cookie value stops working even if it was copied.
 */
export async function logout(req, res) {
  const correlationId = randomUUID();

  try {
    await revokeSession(req.authSession.sessionId);

    const securityEvent = createSessionSecurityEvent({
      eventType: "LOGOUT",
      outcome: "SUCCESS",
      correlationId,
      userId: req.authSession.userId,
    });

    /*
     * Integration point for Sathurshna's common logger:
     *
     * await recordSecurityEvent(securityEvent);
     *
     * Do not send securityEvent to the browser.
     */
    void securityEvent;

    clearSessionCookie(res);

    return res.status(200).json({
      success: true,
      result: "LOGGED_OUT",
    });
  } catch (error) {
    console.error(
      "Logout failed:",
      error.message
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message: "Logout could not be completed.",
      },
    });
  }
}
