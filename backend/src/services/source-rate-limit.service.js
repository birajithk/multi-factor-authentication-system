import { createHash } from "node:crypto";

const DEFAULT_SOURCE_LIMIT = 20;
const DEFAULT_SOURCE_WINDOW_SECONDS = 60;

/**
 * Read a positive integer configuration value.
 *
 * Falls back to the project default if the environment value
 * is absent or invalid.
 */
function readPositiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);

  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }

  return parsed;
}

export const SOURCE_AUTH_LIMIT =
  readPositiveInteger(
    process.env.AUTH_SOURCE_LIMIT,
    DEFAULT_SOURCE_LIMIT,
  );

export const SOURCE_AUTH_WINDOW_SECONDS =
  readPositiveInteger(
    process.env.AUTH_SOURCE_WINDOW_SECONDS,
    DEFAULT_SOURCE_WINDOW_SECONDS,
  );

/**
 * Create a stable server-side key for a source address.
 *
 * The raw address is not stored in the rate-limit event table.
 */
export function buildSourceKey(sourceAddress) {
  const normalizedAddress =
    typeof sourceAddress === "string"
      ? sourceAddress.trim()
      : "";

  return createHash("sha256")
    .update(normalizedAddress || "unknown-source")
    .digest("hex");
}

/**
 * Serialize rate-limit processing for one source.
 *
 * Caller must already be inside a PostgreSQL transaction.
 */
export async function lockSourceRateKey(
  client,
  sourceKey,
) {
  await client.query(
    `
      SELECT pg_advisory_xact_lock(
        hashtextextended($1, 0)
      )
    `,
    [`source:${sourceKey}`],
  );
}

/**
 * Delete events older than the configured rolling window.
 */
export async function removeExpiredSourceEvents(
  client,
  sourceKey,
) {
  await client.query(
    `
      DELETE FROM authentication_source_events
      WHERE source_key = $1
        AND submitted_at <=
          NOW() - ($2 * INTERVAL '1 second')
    `,
    [
      sourceKey,
      SOURCE_AUTH_WINDOW_SECONDS,
    ],
  );
}

/**
 * Check whether another authentication submission is allowed
 * from this source.
 */
export async function getSourceRateStatus(
  client,
  sourceKey,
) {
  await removeExpiredSourceEvents(
    client,
    sourceKey,
  );

  const result = await client.query(
    `
      SELECT
        COUNT(*)::INTEGER AS submission_count,
        MIN(submitted_at) AS oldest_submission
      FROM authentication_source_events
      WHERE source_key = $1
        AND submitted_at >
          NOW() - ($2 * INTERVAL '1 second')
    `,
    [
      sourceKey,
      SOURCE_AUTH_WINDOW_SECONDS,
    ],
  );

  const submissionCount =
    result.rows[0].submission_count;

  const oldestSubmission =
    result.rows[0].oldest_submission;

  const restricted =
    submissionCount >= SOURCE_AUTH_LIMIT;

  let retryAfterSeconds = 0;

  if (restricted && oldestSubmission) {
    const restrictionEnd =
      new Date(oldestSubmission).getTime() +
      SOURCE_AUTH_WINDOW_SECONDS * 1000;

    retryAfterSeconds = Math.max(
      1,
      Math.ceil(
        (restrictionEnd - Date.now()) / 1000,
      ),
    );
  }

  return {
    allowed: !restricted,
    submissionCount,
    submissionLimit: SOURCE_AUTH_LIMIT,
    retryAfterSeconds,
  };
}

/**
 * Record one permitted authentication submission.
 */
export async function recordSourceSubmission(
  client,
  sourceKey,
) {
  await client.query(
    `
      INSERT INTO authentication_source_events (
        source_key
      )
      VALUES ($1)
    `,
    [sourceKey],
  );
}