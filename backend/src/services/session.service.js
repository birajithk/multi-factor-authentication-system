import { createHash, randomBytes, randomUUID } from "node:crypto";
import pool from "../config/database.js";

// ---------------------------------------------------------
// Session design - fixed by SecureByte design
// ---------------------------------------------------------

export const PENDING_SCOPES = Object.freeze({
  ENROLLMENT: "ENROLLMENT",
  MFA_PENDING: "MFA_PENDING",
});

// Separate cookie names so a pending (restricted) token can never
// be read by the full-session guard, and vice versa.
export const PENDING_COOKIE_NAME = "securebyte_pending";
export const SESSION_COOKIE_NAME = "securebyte_session";

export const PENDING_LIFETIME_MINUTES = 5;
export const SESSION_LIFETIME_MINUTES = 30;

// 32 random bytes encoded as base64url = 43 characters.
const TOKEN_BYTES = 32;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

// ---------------------------------------------------------
// Opaque tokens
// ---------------------------------------------------------

/**
 * Generate a new opaque session token.
 *
 * The raw token is only ever sent to the browser in an HttpOnly
 * cookie. It is never stored, logged, or returned in JSON.
 */
export function generateOpaqueToken() {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

/**
 * Hash a token for database storage and lookup.
 *
 * Only this SHA-256 digest is stored, so a database read does
 * not reveal a usable session token.
 */
export function hashToken(token) {
  return createHash("sha256")
    .update(token)
    .digest("hex");
}

/**
 * Reject missing or malformed cookie values before they reach
 * the database.
 */
export function isWellFormedToken(token) {
  return (
    typeof token === "string" &&
    TOKEN_PATTERN.test(token)
  );
}

// ---------------------------------------------------------
// Cookies
// ---------------------------------------------------------

/**
 * Secure is on by default. COOKIE_SECURE=false is only for local
 * HTTP development, where browsers would otherwise drop the
 * cookie.
 */
function isCookieSecure() {
  return process.env.COOKIE_SECURE !== "false";
}

function baseCookieOptions() {
  return {
    httpOnly: true,
    secure: isCookieSecure(),
    sameSite: "lax",
    path: "/",
  };
}

export function setPendingCookie(res, token) {
  res.cookie(PENDING_COOKIE_NAME, token, {
    ...baseCookieOptions(),
    maxAge: PENDING_LIFETIME_MINUTES * 60 * 1000,
  });
}

export function clearPendingCookie(res) {
  res.clearCookie(
    PENDING_COOKIE_NAME,
    baseCookieOptions(),
  );
}

export function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE_NAME, token, {
    ...baseCookieOptions(),
    maxAge: SESSION_LIFETIME_MINUTES * 60 * 1000,
  });
}

export function clearSessionCookie(res) {
  res.clearCookie(
    SESSION_COOKIE_NAME,
    baseCookieOptions(),
  );
}

// ---------------------------------------------------------
// Pending (restricted) transactions
// ---------------------------------------------------------

/**
 * Create a restricted pending transaction for one account.
 *
 * user_id stays server-side. The caller only receives the raw
 * token so it can be placed in the pending cookie.
 *
 * Older pending transactions of the same scope for this account
 * are replaced, and expired rows are removed.
 */
export async function createPendingTransaction({
  userId,
  scope,
}) {
  if (!Object.values(PENDING_SCOPES).includes(scope)) {
    throw new TypeError("Unknown pending scope.");
  }

  const token = generateOpaqueToken();

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      `
        DELETE FROM pending_auth
        WHERE expires_at <= NOW()
           OR (user_id = $1 AND scope = $2)
      `,
      [userId, scope],
    );

    await client.query(
      `
        INSERT INTO pending_auth (
          transaction_id,
          user_id,
          token_hash,
          scope,
          expires_at
        )
        VALUES (
          $1, $2, $3, $4,
          NOW() + ($5 * INTERVAL '1 minute')
        )
      `,
      [
        randomUUID(),
        userId,
        hashToken(token),
        scope,
        PENDING_LIFETIME_MINUTES,
      ],
    );

    await client.query("COMMIT");

    return token;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Find an unexpired pending transaction for exactly one scope.
 *
 * Returns null for a missing, malformed, expired, or
 * wrong-scope token.
 */
export async function findPendingTransaction(token, scope) {
  if (!isWellFormedToken(token)) {
    return null;
  }

  const result = await pool.query(
    `
      SELECT
        p.transaction_id,
        p.user_id,
        p.scope,
        p.failed_attempts,
        p.expires_at,
        u.username,
        u.account_status
      FROM pending_auth p
      JOIN users u ON u.user_id = p.user_id
      WHERE p.token_hash = $1
        AND p.scope = $2
        AND p.expires_at > NOW()
    `,
    [hashToken(token), scope],
  );

  return result.rows[0] ?? null;
}

export async function deletePendingTransaction(transactionId) {
  await pool.query(
    `
      DELETE FROM pending_auth
      WHERE transaction_id = $1
    `,
    [transactionId],
  );
}

// ---------------------------------------------------------
// Full sessions
// ---------------------------------------------------------

/**
 * Insert a full session.
 *
 * The caller must already be inside a PostgreSQL transaction.
 * Only the TOTP login transaction may call this, after both
 * factors have been verified.
 */
export async function insertFullSession(client, userId) {
  const token = generateOpaqueToken();

  await client.query(
    `
      INSERT INTO sessions (
        session_id,
        user_id,
        token_hash,
        expires_at
      )
      VALUES (
        $1, $2, $3,
        NOW() + ($4 * INTERVAL '1 minute')
      )
    `,
    [
      randomUUID(),
      userId,
      hashToken(token),
      SESSION_LIFETIME_MINUTES,
    ],
  );

  return token;
}

/**
 * Find a usable full session.
 *
 * The account must still be ACTIVE on every lookup, so a
 * disabled account loses access immediately.
 */
export async function findActiveSession(token) {
  if (!isWellFormedToken(token)) {
    return null;
  }

  const result = await pool.query(
    `
      SELECT
        s.session_id,
        s.user_id,
        s.created_at,
        s.expires_at,
        u.username,
        u.account_status
      FROM sessions s
      JOIN users u ON u.user_id = s.user_id
      WHERE s.token_hash = $1
        AND s.revoked_at IS NULL
        AND s.expires_at > NOW()
        AND u.account_status = 'ACTIVE'
    `,
    [hashToken(token)],
  );

  return result.rows[0] ?? null;
}

/**
 * Revoke a full session (logout).
 */
export async function revokeSession(sessionId) {
  await pool.query(
    `
      UPDATE sessions
      SET revoked_at = NOW()
      WHERE session_id = $1
        AND revoked_at IS NULL
    `,
    [sessionId],
  );
}
