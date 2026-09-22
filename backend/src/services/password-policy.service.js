import { readFileSync } from "node:fs";

// ---------------------------------------------------------
// Username policy - project implementation decision
// ---------------------------------------------------------

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 50;

// Username is normalized to lowercase before this is checked.
// Allowed:
//   letters
//   numbers
//   dot
//   underscore
//   hyphen
//
// First character must be a letter or number.
const USERNAME_PATTERN = /^[a-z0-9][a-z0-9._-]*$/;

// ---------------------------------------------------------
// Password policy - fixed by SecureByte design
// ---------------------------------------------------------

const PASSWORD_MIN_LENGTH = 15;
const PASSWORD_MAX_LENGTH = 128;

// Load the local password blocklist once when the application starts.
const blocklistPath = new URL(
  "../data/common-passwords.txt",
  import.meta.url,
);

const blockedPasswords = new Set(
  readFileSync(blocklistPath, "utf8")
    .split(/\r?\n/)
    .map((password) => password.trim().toLowerCase())
    .filter(Boolean),
);

/**
 * Convert a username into the canonical form used by the system.
 *
 * Examples:
 * "Birajith"   -> "birajith"
 * " BIRAJITH " -> "birajith"
 */
export function normalizeUsername(username) {
  if (typeof username !== "string") {
    return "";
  }

  return username.trim().toLowerCase();
}

/**
 * Validate a username and return its normalized value.
 */
export function validateUsername(username) {
  const normalizedUsername = normalizeUsername(username);

  if (!normalizedUsername) {
    return {
      valid: false,
      error: "Username is required.",
    };
  }

  const usernameLength = Array.from(normalizedUsername).length;

  if (
    usernameLength < USERNAME_MIN_LENGTH ||
    usernameLength > USERNAME_MAX_LENGTH
  ) {
    return {
      valid: false,
      error: `Username must be between ${USERNAME_MIN_LENGTH} and ${USERNAME_MAX_LENGTH} characters.`,
    };
  }

  if (!USERNAME_PATTERN.test(normalizedUsername)) {
    return {
      valid: false,
      error:
        "Username may contain letters, numbers, dots, underscores, and hyphens, and must start with a letter or number.",
    };
  }

  return {
    valid: true,
    value: normalizedUsername,
  };
}

/**
 * Count Unicode code points instead of JavaScript UTF-16 code units.
 *
 * The password itself is NOT modified.
 */
export function countPasswordCharacters(password) {
  if (typeof password !== "string") {
    return 0;
  }

  return Array.from(password).length;
}

/**
 * Validate the SecureByte password policy.
 *
 * Important:
 * - We never trim the password.
 * - We never lowercase the password before hashing.
 * - We never truncate the password.
 * - Lowercase conversion below is ONLY for blocklist comparison.
 */
export function validatePassword(password) {
  if (typeof password !== "string" || password.length === 0) {
    return {
      valid: false,
      error: "Password is required.",
    };
  }

  const passwordLength = countPasswordCharacters(password);

  if (passwordLength < PASSWORD_MIN_LENGTH) {
    return {
      valid: false,
      error: `Password must contain at least ${PASSWORD_MIN_LENGTH} characters.`,
    };
  }

  if (passwordLength > PASSWORD_MAX_LENGTH) {
    return {
      valid: false,
      error: `Password must not exceed ${PASSWORD_MAX_LENGTH} characters.`,
    };
  }

  if (blockedPasswords.has(password.toLowerCase())) {
    return {
      valid: false,
      error: "Choose a password that is not commonly used or compromised.",
    };
  }

  return {
    valid: true,
  };
}