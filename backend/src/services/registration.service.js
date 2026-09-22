import {
  validateUsername,
  validatePassword,
} from "./password-policy.service.js";

import { hashPassword } from "./password.service.js";

import {
  createEnrollingUser,
  DuplicateUsernameError,
} from "./user.service.js";

/**
 * Register a new SecureByte account.
 *
 * This service:
 * 1. validates the username,
 * 2. validates the password policy,
 * 3. hashes the password using Argon2id,
 * 4. creates an ENROLLING account.
 *
 * It does NOT create a full authenticated session.
 */
export async function registerUser({ username, password }) {
  // ---------------------------------------------------------
  // 1. Validate username
  // ---------------------------------------------------------

  const usernameResult = validateUsername(username);

  if (!usernameResult.valid) {
    return {
      success: false,
      type: "VALIDATION_ERROR",
      field: "username",
      message: usernameResult.error,
    };
  }

  // ---------------------------------------------------------
  // 2. Validate password policy
  // ---------------------------------------------------------

  const passwordResult = validatePassword(password);

  if (!passwordResult.valid) {
    return {
      success: false,
      type: "VALIDATION_ERROR",
      field: "password",
      message: passwordResult.error,
    };
  }

  // ---------------------------------------------------------
  // 3. Hash password
  // ---------------------------------------------------------

  const passwordHash = await hashPassword(password);

  // ---------------------------------------------------------
  // 4. Create restricted ENROLLING account
  // ---------------------------------------------------------

  try {
    const user = await createEnrollingUser({
      username: usernameResult.value,
      passwordHash,
    });

    return {
      success: true,
      user,
    };
  } catch (error) {
    if (error instanceof DuplicateUsernameError) {
      return {
        success: false,
        type: "DUPLICATE_USERNAME",
        field: "username",
        message: "That username is already in use.",
      };
    }

    // Database/network/internal failures are not disguised
    // as successful registration.
    throw error;
  }
}