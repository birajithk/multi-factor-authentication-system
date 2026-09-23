import {
    createTOTPSecret,
    generateTOTPURI,
    verifyTOTPCode,
    getCurrentTOTPStep
} from "../services/totp.service.js";

import {
    encryptSecret,
    decryptSecret
} from "../services/encryption.service.js";

import {
    createTOTPRecord,
    getTOTPRecord,
    completeTOTPEnrollment
} from "../services/totp.repository.js";
/**
 * Start TOTP enrollment.
 *
 * Temporary development authentication:
 * X-User-Id header identifies the test user.
 *
 * This will later be replaced by the authenticated
 * server-side session.
 */
export async function startTOTPEnrollment(req, res) {
    try {
        const userId = req.headers["x-user-id"];

        if (!userId) {
            return res.status(401).json({
                error: "User authentication required."
            });
        }

        // Prevent duplicate TOTP credentials.
        const existingCredential = await getTOTPRecord(userId);

        if (existingCredential) {
            return res.status(409).json({
                error: "TOTP is already configured for this user."
            });
        }

        // Generate a new 160-bit TOTP secret.
        const secret = createTOTPSecret();

        // Encrypt the secret before storing it.
        const encrypted = encryptSecret(secret);

        // Store encrypted secret in PostgreSQL.
        await createTOTPRecord({
            userId,
            encryptedSecret: encrypted.encryptedSecret,
            nonce: encrypted.nonce,
            authTag: encrypted.authTag,
            keyId: encrypted.keyId
        });

        // Generate authenticator-compatible URI.
        const otpAuthUri = generateTOTPURI(
            secret,
            userId,
            "SecureByte"
        );

        /*
         * The setup secret is returned only during enrollment.
         *
         * IMPORTANT:
         * This plaintext secret should NOT be logged or stored
         * anywhere else.
         */
        return res.status(201).json({
            message: "TOTP enrollment started.",
            setupKey: secret,
            otpAuthUri
        });

    } catch (error) {
        console.error(
            "TOTP enrollment error:",
            error
        );

        return res.status(500).json({
            error: "Unable to start TOTP enrollment."
        });
    }
}

/**
 * Verify the TOTP code submitted during enrollment.
 */
export async function verifyTOTPEnrollment(
    req,
    res
) {
    try {
        const userId = req.headers["x-user-id"];
        const { token } = req.body;

        if (!userId) {
            return res.status(401).json({
                error: "User authentication required."
            });
        }

        if (
            typeof token !== "string" ||
            !/^\d{6}$/.test(token)
        ) {
            return res.status(400).json({
                error: "TOTP code must be exactly 6 digits."
            });
        }

        // Retrieve encrypted credential.
        const credential =
            await getTOTPRecord(userId);

        if (!credential) {
            return res.status(404).json({
                error: "TOTP enrollment was not started."
            });
        }

        // Decrypt the server-side TOTP secret.
        const secret = decryptSecret(
            credential.encrypted_secret,
            credential.nonce,
            credential.auth_tag
        );

        // Verify the submitted code.
        const verification =
            await verifyTOTPCode(
                secret,
                token
            );

        if (!verification.valid) {
            return res.status(401).json({
                error: "Invalid TOTP code."
            });
        }

        /*
         * Calculate the actual current TOTP time-step.
         *
         * We use the current server time because the enrollment
         * verification is successful within the configured
         * ±1-step window.
         */
        const currentStep =
            getCurrentTOTPStep();

        /*
         * Atomically:
         *
         * - check replay state
         * - update last_accepted_step
         * - activate the account
         */
        const result =
            await completeTOTPEnrollment(
                userId,
                currentStep
            );

        if (!result.success) {
            if (
                result.reason === "TOTP_REPLAY"
            ) {
                return res.status(409).json({
                    error:
                        "This TOTP time-step has already been used."
                });
            }

            return res.status(400).json({
                error:
                    "Unable to complete TOTP enrollment."
            });
        }

        return res.status(200).json({
            message:
                "TOTP enrollment completed successfully.",
            user: result.user
        });

    } catch (error) {
        console.error(
            "TOTP enrollment verification error:",
            error
        );

        return res.status(500).json({
            error:
                "Unable to verify TOTP enrollment."
        });
    }
}