export const SECOND_FACTOR_FAILURE_LIMIT = 5;
export const SECOND_FACTOR_FAILURE_WINDOW_MINUTES = 15;

/*
 * Per-account second-factor failure budget.
 *
 * TOTP failures record here. Recovery-code failures
 * (Sathurshna's recovery module) must use these same functions
 * so both second factors share ONE budget of 5 failures per
 * account in a rolling 15 minutes.
 */

/**
 * Serialize second-factor processing for one account.
 *
 * The caller must already be inside a PostgreSQL transaction.
 *
 * This prevents simultaneous requests for the same account
 * from independently checking an outdated failure count.
 */
export async function lockSecondFactorAccount(client, userId) {
  await client.query(
    `
      SELECT pg_advisory_xact_lock(
        hashtextextended($1, 0)
      )
    `,
    [`second-factor:${userId}`],
  );
}

/**
 * Remove expired failure records for this account.
 */
export async function removeExpiredSecondFactorFailures(
  client,
  userId,
) {
  await client.query(
    `
      DELETE FROM second_factor_failure_events
      WHERE user_id = $1
        AND failed_at <= NOW() - ($2 * INTERVAL '1 minute')
    `,
    [
      userId,
      SECOND_FACTOR_FAILURE_WINDOW_MINUTES,
    ],
  );
}

/**
 * Check the current rolling second-factor failure budget.
 */
export async function getSecondFactorAttemptStatus(
  client,
  userId,
) {
  await removeExpiredSecondFactorFailures(client, userId);

  const countResult = await client.query(
    `
      SELECT COUNT(*)::INTEGER AS failure_count
      FROM second_factor_failure_events
      WHERE user_id = $1
        AND failed_at > NOW() - ($2 * INTERVAL '1 minute')
    `,
    [
      userId,
      SECOND_FACTOR_FAILURE_WINDOW_MINUTES,
    ],
  );

  const failureCount = countResult.rows[0].failure_count;

  const restricted =
    failureCount >= SECOND_FACTOR_FAILURE_LIMIT;

  let retryAfterSeconds = 0;

  if (restricted) {
    // The account becomes usable again when the failure that
    // brought the count to the limit leaves the window.
    const limitingResult = await client.query(
      `
        SELECT failed_at
        FROM second_factor_failure_events
        WHERE user_id = $1
        ORDER BY failed_at DESC
        OFFSET $2
        LIMIT 1
      `,
      [
        userId,
        SECOND_FACTOR_FAILURE_LIMIT - 1,
      ],
    );

    const restrictionEnd =
      new Date(limitingResult.rows[0].failed_at).getTime() +
      SECOND_FACTOR_FAILURE_WINDOW_MINUTES * 60 * 1000;

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
    failureLimit: SECOND_FACTOR_FAILURE_LIMIT,
    retryAfterSeconds,
  };
}

/**
 * Record one failed second-factor attempt.
 */
export async function recordSecondFactorFailure(
  client,
  userId,
) {
  await client.query(
    `
      INSERT INTO second_factor_failure_events (
        user_id
      )
      VALUES ($1)
    `,
    [userId],
  );
}
