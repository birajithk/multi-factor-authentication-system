import { registerUser } from "../services/registration.service.js";

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
    console.error("Registration failed:", error);

    return res.status(500).json({
      success: false,
      error: {
        type: "INTERNAL_ERROR",
        message: "Registration could not be completed.",
      },
    });
  }
}