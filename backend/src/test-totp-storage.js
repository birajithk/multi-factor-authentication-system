import "dotenv/config";

import {
    createTOTPSecret,
    generateTOTPCode,
    verifyTOTPCode
} from "./services/totp.service.js";

import {
    encryptSecret,
    decryptSecret
} from "./services/encryption.service.js";

import {
    createTOTPRecord,
    getTOTPRecord
} from "./services/totp.repository.js";

const TEST_USER_ID =
    "11111111-1111-1111-1111-111111111111";

try {
    console.log("=== TOTP STORAGE INTEGRATION TEST ===\n");

    // 1. Generate TOTP secret
    const secret = createTOTPSecret();

    console.log("1. Generated TOTP secret");
    console.log(`   Length: ${secret.length} characters`);

    // 2. Encrypt the secret
    const encrypted = encryptSecret(secret);

    console.log("\n2. Encrypted TOTP secret");
    console.log(`   Key ID: ${encrypted.keyId}`);
    console.log(`   Encrypted secret: ${encrypted.encryptedSecret}`);
    console.log(`   Nonce: ${encrypted.nonce}`);
    console.log(`   Auth tag: ${encrypted.authTag}`);

    // 3. Store encrypted secret in PostgreSQL
    const stored = await createTOTPRecord({
        userId: TEST_USER_ID,
        encryptedSecret: encrypted.encryptedSecret,
        nonce: encrypted.nonce,
        authTag: encrypted.authTag,
        keyId: encrypted.keyId
    });

    console.log("\n3. Stored TOTP credential in PostgreSQL");
    console.log(stored);

    // 4. Retrieve from PostgreSQL
    const record = await getTOTPRecord(TEST_USER_ID);

    if (!record) {
        throw new Error("TOTP record was not found.");
    }

    console.log("\n4. Retrieved encrypted credential from PostgreSQL");

    // 5. Decrypt the secret
    const decryptedSecret = decryptSecret(
        record.encrypted_secret,
        record.nonce,
        record.auth_tag
    );

    console.log("\n5. Decrypted TOTP secret");

    // Do NOT print the actual secret.
    console.log(
        `   Secret recovered: ${
            decryptedSecret === secret ? "YES" : "NO"
        }`
    );

    // 6. Generate TOTP using decrypted secret
    const code = await generateTOTPCode(
        decryptedSecret
    );

    console.log("\n6. Generated TOTP code from decrypted secret");
    console.log(`   Code: ${code}`);

    // 7. Verify the code
    const verification = await verifyTOTPCode(
        decryptedSecret,
        code
    );

    console.log("\n7. TOTP verification result");
    console.log(verification);

    // Final checks
    if (
        decryptedSecret !== secret ||
        verification.valid !== true
    ) {
        throw new Error(
            "TOTP storage integration test FAILED."
        );
    }

    console.log(
        "\n=== TOTP STORAGE INTEGRATION TEST PASSED ==="
    );

} catch (error) {
    console.error(
        "\n=== TOTP STORAGE INTEGRATION TEST ERROR ==="
    );

    console.error(error);

    process.exitCode = 1;
}
