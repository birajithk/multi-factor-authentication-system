import {
    createTOTPSecret,
    generateTOTPURI,
    verifyTOTPCode
} from "../services/totp.service.js";

import {
    encryptSecret,
    decryptSecret
} from "../services/encryption.service.js";

import {
    upsertUnverifiedTOTPRecord,
    getTOTPRecord,
    completeTOTPEnrollment
} from "../services/totp.repository.js";

import {
    PENDING_COOKIE_NAME,
    PENDING_SCOPES,
    findPendingTransaction,
    deletePendingTransaction,
    clearPendingCookie
} from "../services/session.service.js";

/**
 * Load the ENROLLMENT pending transaction from its HttpOnly
 * cookie.
 *
 * This is the ONLY accepted identity for enrollment. Headers,
 * body fields, MFA_PENDING tokens, and full sessions are not
 * accepted, and the account must still be ENROLLING.
 */
async function loadEnrollmentTransaction(req) {
    const pending = await findPendingTransaction(
        req.cookies?.[PENDING_COOKIE_NAME],
        PENDING_SCOPES.ENROLLMENT
    );

    if (
        !pending ||
        pending.account_status !== "ENROLLING"
    ) {
        return null;
    }

    return pending;
}

function enrollmentAuthenticationRequired(res) {
    return res.status(401).json({
        success: false,
        error: {
            type: "AUTHENTICATION_REQUIRED",
            message:
                "Enrollment session is missing or expired. Sign in again."
        }
    });
}

/**
 * Start TOTP enrollment.
 *
 * Requires the ENROLLMENT pending cookie created by
 * registration or by password login of an ENROLLING account.
 */
export async function startTOTPEnrollment(req, res) {
    try {
        const pending =
            await loadEnrollmentTransaction(req);

        if (!pending) {
            return enrollmentAuthenticationRequired(res);
        }

        const userId = pending.user_id;

        // Generate a new 160-bit TOTP secret.
        const secret = createTOTPSecret();

        // Encrypt the secret before storing it.
        const encrypted = encryptSecret(secret);

        /*
         * Store encrypted secret in PostgreSQL.
         *
         * An unverified credential from an interrupted enrollment
         * is replaced. A verified credential is never replaced.
         */
        const stored = await upsertUnverifiedTOTPRecord({
            userId,
            encryptedSecret: encrypted.encryptedSecret,
            nonce: encrypted.nonce,
            authTag: encrypted.authTag,
            keyId: encrypted.keyId
        });

        if (!stored) {
            return res.status(409).json({
                error: "TOTP is already configured for this user."
            });
        }

        // Generate authenticator-compatible URI.
        // The label is the username, not the internal user_id.
        const otpAuthUri = generateTOTPURI(
            secret,
            pending.username,
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
 *
 * Success activates the account but does NOT create a full
 * session. The user must then sign in normally
 * (password + TOTP).
 */
export async function verifyTOTPEnrollment(
    req,
    res
) {
    try {
        const { token } = req.body ?? {};

        const pending =
            await loadEnrollmentTransaction(req);

        if (!pending) {
            return enrollmentAuthenticationRequired(res);
        }

        const userId = pending.user_id;

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
         * Use the exact time-step the code matched
         * (otplib VerifyResult.timeStep), not the current server
         * step. Otherwise a code that matched the NEXT step
         * (client clock ahead) could be replayed at login.
         */
        const matchedStep = verification.timeStep;

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
                matchedStep
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

        /*
         * Enrollment is finished, so the enrollment scope ends.
         * No full session is created here.
         */
        await deletePendingTransaction(
            pending.transaction_id
        );

        clearPendingCookie(res);

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