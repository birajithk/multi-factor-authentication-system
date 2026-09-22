import { randomUUID } from "node:crypto";
import pool from "../config/database.js";
import { normalizeUsername } from "./password-policy.service.js";

/**
 * Special error used when registration attempts to create
 * a username that already exists.
 */
export class DuplicateUsernameError extends Error {
  constructor() {
    super("Username already exists.");
    this.name = "DuplicateUsernameError";
  }
}

/**
 * Find an account using the system's case-insensitive
 * username comparison rule.
 *
 * Returns:
 *   user object -> when found
 *   null        -> when not found
 */
export async function findUserByUsername(username) {
  const normalizedUsername = normalizeUsername(username);

  if (!normalizedUsername) {
    return null;
  }

  const result = await pool.query(
    `
      SELECT
        user_id,
        username,
        password_hash,
        account_status,
        created_at
      FROM users
      WHERE LOWER(username) = LOWER($1)
      LIMIT 1
    `,
    [normalizedUsername],
  );

  return result.rows[0] ?? null;
}

/**
 * Create a new account in the restricted ENROLLING state.
 *
 * Registration must never create an ACTIVE account directly.
 */
export async function createEnrollingUser({
  username,
  passwordHash,
}) {
  const normalizedUsername = normalizeUsername(username);

  if (!normalizedUsername) {
    throw new TypeError("Username is required.");
  }

  if (
    typeof passwordHash !== "string" ||
    passwordHash.length === 0
  ) {
    throw new TypeError("Password hash is required.");
  }

  const userId = randomUUID();

  try {
    const result = await pool.query(
      `
        INSERT INTO users (
          user_id,
          username,
          password_hash,
          account_status
        )
        VALUES ($1, $2, $3, 'ENROLLING')
        RETURNING
          user_id,
          username,
          account_status,
          created_at
      `,
      [
        userId,
        normalizedUsername,
        passwordHash,
      ],
    );

    return result.rows[0];
  } catch (error) {
    // PostgreSQL error code 23505 = unique constraint violation.
    //
    // This includes our case-insensitive username index,
    // so "Birajith" and "BIRAJITH" cannot become separate accounts.
    if (error.code === "23505") {
      throw new DuplicateUsernameError();
    }

    throw error;
  }
}