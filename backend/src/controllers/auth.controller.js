import { registerUser } from "../services/registration.service.js";
import { randomUUID } from "node:crypto";
import {
  verifyFirstFactor,
} from "../services/password-authentication.service.js";

import {
  consumeSourceAuthenticationSubmission,
} from "../services/source-rate-limit.service.js";

import {
  createPasswordSecurityEvent,
} from "../services/password-event-metadata.service.js";

/**
 * POST /api/auth/register
 *
 * Creates a new account in ENROLLING state.
 *
 * Successful registration does NOT mean that the user has
 * completed MFA and does NOT grant access to protected content.
 */
export async function register(req, res) {
  const { username, password } = req.body ?? {};

  try {
    const result = await registerUser({
      username,
      password,
    });

    if (!result.success) {
      if (result.type === "VALIDATION_ERROR") {
        return res.status(400).json({
          success: false,
          error: {
            type: result.type,
            field: result.field,
            message: result.message,
          },
        });
      }

      if (result.type === "DUPLICATE_USERNAME") {
        return res.status(409).json({
          success: false,
          error: {
            type: result.type,
            field: result.field,
            message: result.message,
          },
        });
      }

      return res.status(400).json({
        success: false,
        error: {
          type: "REGISTRATION_FAILED",
          message: "Registration could not be completed.",
        },
      });
    }

    return res.status(201).json({
      success: true,

      user: {
        user_id: result.user.user_id,
        username: result.user.username,
        account_status: result.user.account_status,
        created_at: result.user.created_at,
      },

      /*
       * This tells the shared controller/UI what operation comes next.
       *
       * It is NOT proof of authentication and does not grant
       * dashboard access.
       *
       * The enrollment-only session itself will be integrated with
       * Khamshayan/Abishek's session flow.
       */
      next_step: "AUTHENTICATOR_ENROLLMENT",
    });
  } catch (error) {
    console.error(
        "Registration failed:",
        error
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message: "Registration could not be completed.",
      },
    });
  }
}

/**
 * POST /api/auth/password
 *
 * Verifies the password first factor only.
 *
 * IMPORTANT:
 * A successful response does NOT represent completed MFA and
 * does NOT grant access to protected application resources.
 */
export async function verifyPasswordFactor(req, res) {
  const { username, password } = req.body ?? {};
  const correlationId = randomUUID();

  try {
    // -------------------------------------------------------
    // 1. Basic request validation
    // -------------------------------------------------------

    if (
      typeof username !== "string" ||
      username.trim().length === 0
    ) {
      return res.status(400).json({
        success: false,
        error: {
          type: "VALIDATION_ERROR",
          field: "username",
          message: "Username is required.",
        },
      });
    }

    if (
      typeof password !== "string" ||
      password.length === 0
    ) {
      return res.status(400).json({
        success: false,
        error: {
          type: "VALIDATION_ERROR",
          field: "password",
          message: "Password is required.",
        },
      });
    }

    // -------------------------------------------------------
    // 2. Supplementary source-address budget
    //
    // req.ip is used as the application-visible source.
    // Proxy handling must be configured by the deployment
    // environment before trusting forwarded addresses.
    // -------------------------------------------------------

    const sourceStatus =
      await consumeSourceAuthenticationSubmission(
        req.ip,
      );

      if (!sourceStatus.allowed) {
          const securityEvent =
          createPasswordSecurityEvent({
              eventType: "TEMPORARY_RESTRICTION",
              outcome: "BLOCKED",
              correlationId,
              userId: null,
          });

        /*
        * Integration point for Sathurshna's common logger:
        *
        * await recordSecurityEvent(securityEvent);
        *
        * userId is null because the source budget is checked
        * before account verification.
        */
          void securityEvent;
      res.set(
        "Retry-After",
        String(sourceStatus.retryAfterSeconds),
      );

      return res.status(429).json({
        success: false,
        error: {
          type: "TEMPORARILY_RESTRICTED",
          message:
            "Too many authentication attempts. Try again later.",
          retry_after_seconds:
            sourceStatus.retryAfterSeconds,
        },
      });
    }

    // -------------------------------------------------------
    // 3. Verify factor 1
    // -------------------------------------------------------

    const result = await verifyFirstFactor({
      username,
      password,
      correlationId,
    });

    /*
    * Integration point for Sathurshna's common logger:
    *
    * await recordSecurityEvent(result.securityEvent);
    *
    * Do not send securityEvent to the browser.
    */
    const securityEvent = result.securityEvent;
    void securityEvent;

    if (!result.success) {
      if (
        result.type === "TEMPORARILY_RESTRICTED"
      ) {
        res.set(
          "Retry-After",
          String(result.retry_after_seconds),
        );

        return res.status(429).json({
          success: false,
          error: {
            type: "TEMPORARILY_RESTRICTED",
            message: result.message,
            retry_after_seconds:
              result.retry_after_seconds,
          },
        });
      }

      return res.status(401).json({
        success: false,
        error: {
          type: "AUTHENTICATION_FAILED",
          message: "Invalid username or password.",
        },
      });
    }

    // -------------------------------------------------------
    // 4. Determine the permitted next operation
    //
    // This does NOT create full authentication.
    // Khamshayan/Abishek's shared controller/session integration
    // must create the appropriate server-side restricted scope.
    // -------------------------------------------------------

    let nextStep;

    switch (result.account.account_status) {
      case "ENROLLING":
        nextStep = "AUTHENTICATOR_ENROLLMENT";
        break;

      case "ACTIVE":
        nextStep = "TOTP_VERIFICATION";
        break;

      case "RECOVERY_REQUIRED":
        nextStep = "RECOVERY_CODE_VERIFICATION";
        break;

      default:
        return res.status(401).json({
          success: false,
          error: {
            type: "AUTHENTICATION_FAILED",
            message: "Invalid username or password.",
          },
        });
    }

    return res.status(200).json({
      success: true,
      result: "PASSWORD_VERIFIED",
      user_id: result.account.user_id,
      account_status:
        result.account.account_status,
      next_step: nextStep,
    });
  } catch (error) {
    console.error(
      "Password authentication failed:",
      error,
    );

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message:
          "Authentication could not be completed.",
      },
    });
  }
}