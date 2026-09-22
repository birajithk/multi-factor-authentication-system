import argon2 from "argon2";

// SecureByte Argon2id configuration.
//
// The argon2 npm package expects memoryCost in KiB.
// 19 MiB = 19 * 1024 KiB = 19456 KiB.
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

/*
 * This value is NOT a real user password.
 *
 * We create a dummy Argon2id verifier when the module starts.
 * Later, if somebody tries to log in with a username that does not exist,
 * the authentication flow can still perform an expensive Argon2 verify
 * instead of returning immediately.
 *
 * This helps reduce obvious timing differences between:
 *   - unknown username
 *   - known username + wrong password
 */
const DUMMY_PASSWORD = "SecureByte dummy password verification value";

const DUMMY_PASSWORD_HASH = await argon2.hash(
  DUMMY_PASSWORD,
  ARGON2_OPTIONS,
);

/**
 * Hash a password using the SecureByte Argon2id configuration.
 *
 * The Argon2 library generates a fresh random salt automatically.
 *
 * @param {string} password
 * @returns {Promise<string>} encoded Argon2id hash
 */
export async function hashPassword(password) {
  if (typeof password !== "string") {
    throw new TypeError("Password must be a string.");
  }

  return argon2.hash(password, ARGON2_OPTIONS);
}

/**
 * Verify a supplied password against an encoded Argon2id hash.
 *
 * @param {string} encodedHash
 * @param {string} password
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(encodedHash, password) {
  if (typeof encodedHash !== "string") {
    throw new TypeError("Encoded password hash must be a string.");
  }

  if (typeof password !== "string") {
    throw new TypeError("Password must be a string.");
  }

  try {
    return await argon2.verify(encodedHash, password);
  } catch {
    return false;
  }
}

/**
 * Perform password verification work for an unknown account.
 *
 * The result is deliberately ignored by the authentication flow.
 * An unknown username must still result in generic authentication failure.
 *
 * @param {string} suppliedPassword
 * @returns {Promise<void>}
 */
export async function performDummyPasswordVerification(suppliedPassword) {
  if (typeof suppliedPassword !== "string") {
    suppliedPassword = "";
  }

  try {
    await argon2.verify(DUMMY_PASSWORD_HASH, suppliedPassword);
  } catch {
    // Deliberately do nothing.
    // This function never authenticates a user.
  }
}