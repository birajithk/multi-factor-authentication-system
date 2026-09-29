import {
    generateSecret,
    generate,
    verify,
    generateURI
} from "otplib";

import { crypto } from "@otplib/plugin-crypto-node";
import { base32 } from "@otplib/plugin-base32-scure";

const TOTP_CONFIG = {
    crypto,
    base32,
    algorithm: "sha1",
    digits: 6,
    period: 30,
    t0: 0,
    epochTolerance: 30
};

/**
 * Generate a 160-bit TOTP secret.
 *
 * 20 bytes × 8 = 160 bits.
 */
export function createTOTPSecret() {
    return generateSecret({
        crypto,
        base32,
        length: 20
    });
}

/**
 * Generate the current 6-digit TOTP code.
 */
export async function generateTOTPCode(secret) {
    return await generate({
        ...TOTP_CONFIG,
        secret
    });
}

/**
 * Verify a TOTP code.
 *
 * window = 1:
 * current 30-second time-step ± one time-step.
 *
 * A valid result includes timeStep, the exact RFC 6238
 * time-step the code matched. Callers must use it
 * for replay protection.
 */
export async function verifyTOTPCode(secret, token) {
    return await verify({
        ...TOTP_CONFIG,
        secret,
        token
    });
}

/**
 * Generate an otpauth URI for authenticator applications.
 */
export function generateTOTPURI(
    secret,
    username,
    issuer = "SecureByte"
) {
    return generateURI({
        ...TOTP_CONFIG,
        secret,
        issuer,
        label: username
    });
}

/**
 * Calculate the current Unix TOTP time-step.
 *
 * TOTP period = 30 seconds.
 */
export function getCurrentTOTPStep() {
    return Math.floor(
        Date.now() / 1000 / 30
    );
}