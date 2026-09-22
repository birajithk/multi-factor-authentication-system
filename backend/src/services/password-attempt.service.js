import { createHash } from "node:crypto";
import { normalizeUsername } from "./password-policy.service.js";

const PASSWORD_FAILURE_LIMIT = 5;
const PASSWORD_FAILURE_WINDOW_MINUTES = 15;

/**
 * Build the server-side key used for password retry tracking.
 *
 * Existing accounts are tracked by user_id.
 *
 * Unknown usernames use a SHA-256 digest so attempted login
 * identifiers are not stored directly in the retry table.
 */
export function buildPasswordRetryKey({ user, username }) {
  if (user?.user_id) {
    return `user:${user.user_id}`;
  }

  const normalizedUsername = normalizeUsername(username);

  const identifierHash = createHash("sha256")
    .update(normalizedUsername)
    .digest("hex");

  return `unknown:${identifierHash}`;
}

/**
 * Serialize password-attempt processing for one retry key.
 *
 * The caller must already be inside a PostgreSQL transaction.
 *
 * This prevents simultaneous requests for the same account
 * from independently checking an outdated failure count.
 */
export async function lockPasswordAttemptKey(client, retryKey) {
  await client.query(
    `
      SELECT pg_advisory_xact_lock(
        hashtextextended($1, 0)
      )
    `,
    [retryKey],
  );
}

/**
 * Remove expired failure records for this retry key.
 *
 * Only failures inside the rolling 15-minute window matter.
 */
export async function removeExpiredPasswordFailures(
  client,
  retryKey,
) {
  await client.query(
    `
      DELETE FROM password_failure_events
      WHERE retry_key = $1
        AND failed_at <= NOW() - INTERVAL '15 minutes'
    `,
    [retryKey],
  );
}

/**
 * Check the current rolling account failure budget.
 */
export async function getPasswordAttemptStatus(
  client,
  retryKey,
) {
  await removeExpiredPasswordFailures(client, retryKey);

  const result = await client.query(
    `
      SELECT
        COUNT(*)::INTEGER AS failure_count,
        MIN(failed_at) AS oldest_failure
      FROM password_failure_events
      WHERE retry_key = $1
        AND failed_at > NOW() - INTERVAL '15 minutes'
    `,
    [retryKey],
  );

  const failureCount = result.rows[0].failure_count;
  const oldestFailure = result.rows[0].oldest_failure;

  const restricted =
    failureCount >= PASSWORD_FAILURE_LIMIT;

  let retryAfterSeconds = 0;

  if (restricted && oldestFailure) {
    const restrictionEnd =
      new Date(oldestFailure).getTime() +
      PASSWORD_FAILURE_WINDOW_MINUTES * 60 * 1000;

    retryAfterSeconds = Math.max(
      1,
      Math.ceil(
        (restrictionEnd - Date.now()) / 1000,
      ),
    );
  }

  return {
    allowed: !restricted,
    failureCount,
    failureLimit: PASSWORD_FAILURE_LIMIT,
    retryAfterSeconds,
  };
}

/**
 * Record one failed password attempt.
 *
 * userId is null for an unknown username.
 */
export async function recordPasswordFailure(
  client,
  {
    retryKey,
    userId = null,
  },
) {
  await client.query(
    `
      INSERT INTO password_failure_events (
        retry_key,
        user_id
      )
      VALUES ($1, $2)
    `,
    [
      retryKey,
      userId,
    ],
  );
}