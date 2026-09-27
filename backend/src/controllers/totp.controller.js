import pool from "../config/database.js";
import {
    createTOTPSecret,
    generateTOTPCode,
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
        const userId = req.headers["x-user-id"] || req.body?.userId;

        if (!userId) {
            return res.status(401).json({
                error: "User authentication required."
            });
        }

        // Check user account status
        const userResult = await pool.query(
            "SELECT account_status FROM users WHERE user_id = $1",
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        const userStatus = userResult.rows[0].account_status;

        // An ACTIVE account cannot bypass recovery to redo initial setup
        if (userStatus === "ACTIVE") {
            return res.status(409).json({
                error: "TOTP is already active for this account. Use recovery to replace."
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
         * In development mode, we also include the current server-generated code
         * to facilitate immediate local testing across system clock variations.
         */
        const demoCode = await generateTOTPCode(secret);

        return res.status(201).json({
            message: "TOTP enrollment started.",
            setupKey: secret,
            otpAuthUri,
            demoCode
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
        const userId = req.headers["x-user-id"] || req.body?.userId;
        const rawToken = req.body?.token;
        const token = typeof rawToken === "string" ? rawToken.replace(/\s+/g, "").trim() : "";

        if (!userId) {
            return res.status(401).json({
                error: "User authentication required."
            });
        }

        if (!/^\d{6}$/.test(token)) {
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

/**
 * Verify TOTP code for standard two-factor authentication login.
 */
export async function verifyTOTPLogin(req, res) {
    const client = await pool.connect();
    try {
        const userId = req.headers["x-user-id"] || req.body?.userId;
        const rawToken = req.body?.token;
        const token = typeof rawToken === "string" ? rawToken.replace(/\s+/g, "").trim() : "";

        if (!userId) {
            return res.status(401).json({
                error: "User authentication context required."
            });
        }

        if (!/^\d{6}$/.test(token)) {
            return res.status(400).json({
                error: "TOTP code must be exactly 6 digits."
            });
        }

        const credential = await getTOTPRecord(userId);
        if (!credential) {
            return res.status(404).json({
                error: "No TOTP credential configured for this user."
            });
        }

        const secret = decryptSecret(
            credential.encrypted_secret,
            credential.nonce,
            credential.auth_tag
        );

        const verification = await verifyTOTPCode(secret, token);
        if (!verification.valid) {
            return res.status(401).json({
                error: "Invalid authenticator code."
            });
        }

        const currentStep = getCurrentTOTPStep();

        await client.query("BEGIN");

        const lockResult = await client.query(
            `SELECT last_accepted_step FROM totp_credentials WHERE user_id = $1 FOR UPDATE`,
            [userId]
        );

        if (lockResult.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({ error: "Credential not found." });
        }

        const lastAccepted = lockResult.rows[0].last_accepted_step;
        if (lastAccepted !== null && currentStep <= Number(lastAccepted)) {
            await client.query("ROLLBACK");
            return res.status(409).json({
                error: "This TOTP code has already been used. Please wait for the next code."
            });
        }

        await client.query(
            `UPDATE totp_credentials SET last_accepted_step = $2, updated_at = NOW() WHERE user_id = $1`,
            [userId, currentStep]
        );

        const userResult = await client.query(
            `SELECT user_id, username, account_status, created_at FROM users WHERE user_id = $1`,
            [userId]
        );

        await client.query("COMMIT");

        return res.status(200).json({
            success: true,
            result: "MFA_AUTHENTICATED",
            message: "Two-factor authentication successful.",
            user: userResult.rows[0]
        });

    } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        console.error("TOTP login verification error:", error);
        return res.status(500).json({
            error: "Unable to verify login authenticator code."
        });
    } finally {
        client.release();
    }
}