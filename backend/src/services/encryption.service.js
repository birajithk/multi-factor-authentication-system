import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const KEY_ID = "local-dev-key-v1";

function getEncryptionKey() {
    const key = process.env.TOTP_ENCRYPTION_KEY;

    if (!key) {
        throw new Error("TOTP_ENCRYPTION_KEY is not configured.");
    }

    const encryptionKey = Buffer.from(key, "hex");

    if (encryptionKey.length !== 32) {
        throw new Error(
            "TOTP_ENCRYPTION_KEY must represent exactly 32 bytes."
        );
    }

    return encryptionKey;
}

export function encryptSecret(plaintext) {
    const key = getEncryptionKey();

    // AES-GCM requires a fresh nonce for every encryption.
    const nonce = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv(
        ALGORITHM,
        key,
        nonce
    );

    const encrypted = Buffer.concat([
        cipher.update(plaintext, "utf8"),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return {
        encryptedSecret: encrypted.toString("base64"),
        nonce: nonce.toString("base64"),
        authTag: authTag.toString("base64"),
        keyId: KEY_ID
    };
}

export function decryptSecret(
    encryptedSecret,
    nonce,
    authTag
) {
    const key = getEncryptionKey();

    const decipher = crypto.createDecipheriv(
        ALGORITHM,
        key,
        Buffer.from(nonce, "base64")
    );

    decipher.setAuthTag(
        Buffer.from(authTag, "base64")
    );

    const decrypted = Buffer.concat([
        decipher.update(
            Buffer.from(encryptedSecret, "base64")
        ),
        decipher.final()
    ]);

    return decrypted.toString("utf8");
}
