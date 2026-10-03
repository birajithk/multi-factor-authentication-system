import crypto from "node:crypto";
import db from "../config/database.js";

import {
  SecurityLogger,
} from "./security-logger.service.js";

import {
  generateOpaqueToken,
  hashToken,
  isWellFormedToken,
} from "./session.service.js";

import {
  lockSecondFactorAccount,
  getSecondFactorAttemptStatus,
  recordSecondFactorFailure,
} from "./second-factor-attempt.service.js";

export const RECOVERY_COOKIE_NAME =
  "recovery_session";

export const RECOVERY_SCOPE =
  "RECOVERY_ONLY";

export const RECOVERY_SESSION_LIFETIME_MINUTES =
  5;

export class RecoveryService {
  /**
   * Generate 10 new recovery codes.
   *
   * Plaintext values are returned once to the user.
   * Only salted hashes are stored in PostgreSQL.
   */
  static async generateRecoveryCodes(userId) {
    const plainCodes = [];
    const hashedCodes = [];

    for (let i = 0; i < 10; i++) {
      // 128 random bits.
      const code =
        crypto.randomBytes(16).toString("hex");

      const normalizedCode =
        this.normalizeCode(code);

      const salt =
        crypto.randomBytes(16).toString("hex");

      const hash = crypto
        .createHash("sha256")
        .update(normalizedCode + salt)
        .digest("hex");

      plainCodes.push(code);

      hashedCodes.push({
        codeId: crypto.randomUUID(),
        userId,
        salt,
        hash,
      });
    }

    const client = await db.connect();

    try {
      await client.query("BEGIN");

      /*
       * Replacing a recovery set revokes all unused codes
       * from the previous set.
       */
      await client.query(
        `
          UPDATE recovery_codes
          SET revoked_time = NOW()
          WHERE user_id = $1
            AND used_time IS NULL
            AND revoked_time IS NULL
        `,
        [userId],
      );

      for (const item of hashedCodes) {
        await client.query(
          `
            INSERT INTO recovery_codes (
              code_id,
              user_id,
              salt,
              code_hash,
              issued_time
            )
            VALUES ($1, $2, $3, $4, NOW())
          `,
          [
            item.codeId,
            item.userId,
            item.salt,
            item.hash,
          ],
        );
      }

      await client.query("COMMIT");

      await SecurityLogger.logEvent({
        event_type:
          "RECOVERY_CODE_REGENERATION",
        outcome: "SUCCESS",
        user_id: userId,
      });

      return plainCodes;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Normalize a recovery code before hashing/checking.
   */
  static normalizeCode(code) {
    return code
      .replace(/[^a-fA-F0-9]/g, "")
      .toLowerCase();
  }

  /**
   * Use one recovery code as the alternative second factor.
   *
   * On success this transaction:
   *
   * 1. consumes exactly one recovery code,
   * 2. marks the account RECOVERY_REQUIRED,
   * 3. removes the old TOTP credential,
   * 4. revokes full sessions,
   * 5. removes pending authentication,
   * 6. creates a recovery-only session.
   *
   * The browser receives the RAW recovery token.
   * PostgreSQL stores only SHA-256(raw token).
   */
  static async consumeRecoveryCode(
    userId,
    submittedCode,
  ) {
    const normalizedCode =
      this.normalizeCode(submittedCode);

    const client = await db.connect();

    try {
      await client.query("BEGIN");

      /*
       * Serialize TOTP/recovery second-factor attempts for
       * this account.
       */
      await lockSecondFactorAccount(
        client,
        userId,
      );

      /*
       * Recovery and TOTP share the same rolling
       * 5-failures / 15-minute budget.
       */
      const attemptStatus =
        await getSecondFactorAttemptStatus(
          client,
          userId,
        );

      if (!attemptStatus.allowed) {
        await client.query("COMMIT");

        return {
          success: false,
          type: "TEMPORARILY_RESTRICTED",
          retryAfterSeconds:
            attemptStatus.retryAfterSeconds,
        };
      }

      /*
       * Lock usable recovery-code rows.
       *
       * This prevents two concurrent requests from consuming
       * the same code.
       */
      const result = await client.query(
        `
          SELECT
            code_id,
            salt,
            code_hash
          FROM recovery_codes
          WHERE user_id = $1
            AND used_time IS NULL
            AND revoked_time IS NULL
          FOR UPDATE
        `,
        [userId],
      );

      let matchedCodeId = null;

      for (const record of result.rows) {
        const computedHash = crypto
          .createHash("sha256")
          .update(
            normalizedCode + record.salt,
          )
          .digest("hex");

        const computedBuffer =
          Buffer.from(computedHash, "hex");

        const storedBuffer =
          Buffer.from(
            record.code_hash,
            "hex",
          );

        if (
          computedBuffer.length ===
            storedBuffer.length &&
          crypto.timingSafeEqual(
            computedBuffer,
            storedBuffer,
          )
        ) {
          matchedCodeId = record.code_id;
          break;
        }
      }

      /*
       * Invalid recovery code.
       */
      if (!matchedCodeId) {
        await recordSecondFactorFailure(
          client,
          userId,
        );

        await client.query("COMMIT");

        await SecurityLogger.logEvent({
          event_type:
            "RECOVERY_CODE_USE",
          outcome: "FAILURE",
          user_id: userId,
        });

        return {
          success: false,
          type: "INVALID_CODE",
        };
      }

      /*
       * Consume exactly one code.
       */
      const consumeResult =
        await client.query(
          `
            UPDATE recovery_codes
            SET used_time = NOW()
            WHERE code_id = $1
              AND used_time IS NULL
              AND revoked_time IS NULL
          `,
          [matchedCodeId],
        );

      if (consumeResult.rowCount !== 1) {
        await recordSecondFactorFailure(
          client,
          userId,
        );

        await client.query("COMMIT");

        await SecurityLogger.logEvent({
          event_type:
            "RECOVERY_CODE_USE",
          outcome: "FAILURE",
          user_id: userId,
        });

        return {
          success: false,
          type: "INVALID_CODE",
        };
      }

      /*
       * Enter restricted recovery state.
       */
      const accountResult =
        await client.query(
          `
            UPDATE users
            SET account_status =
              'RECOVERY_REQUIRED'
            WHERE user_id = $1
              AND account_status IN (
                'ACTIVE',
                'RECOVERY_REQUIRED'
              )
            RETURNING user_id
          `,
          [userId],
        );

      if (accountResult.rowCount !== 1) {
        throw new Error(
          "Account is not eligible for recovery.",
        );
      }

      /*
       * Revoke the old authenticator.
       */
      await client.query(
        `
          DELETE FROM totp_credentials
          WHERE user_id = $1
        `,
        [userId],
      );

      /*
       * Revoke existing full sessions.
       */
      await client.query(
        `
          UPDATE sessions
          SET revoked_at = NOW()
          WHERE user_id = $1
            AND revoked_at IS NULL
        `,
        [userId],
      );

      /*
       * Consume all pending authentication state.
       */
      await client.query(
        `
          DELETE FROM pending_auth
          WHERE user_id = $1
        `,
        [userId],
      );

      /*
       * Replace any older recovery-only session.
       */
      await client.query(
        `
          DELETE FROM recovery_sessions
          WHERE user_id = $1
        `,
        [userId],
      );

      /*
       * Generate an opaque recovery credential.
       *
       * RAW token → browser.
       * SHA-256(raw token) → PostgreSQL.
       */
      const recoveryToken =
        generateOpaqueToken();

      const identifierHash =
        hashToken(recoveryToken);

      await client.query(
        `
          INSERT INTO recovery_sessions (
            identifier_hash,
            user_id,
            scope,
            expiry,
            extension_count
          )
          VALUES (
            $1,
            $2,
            $3,
            NOW() + ($4 * INTERVAL '1 minute'),
            0
          )
        `,
        [
          identifierHash,
          userId,
          RECOVERY_SCOPE,
          RECOVERY_SESSION_LIFETIME_MINUTES,
        ],
      );

      await client.query("COMMIT");

      await SecurityLogger.logEvent({
        event_type:
          "RECOVERY_CODE_USE",
        outcome: "SUCCESS",
        user_id: userId,
      });

      return {
        success: true,
        recoveryToken,
      };
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Validate an active recovery-only session.
   *
   * Used later by requireRecoverySession middleware.
   */
  static async findActiveRecoverySession(
    token,
  ) {
    if (!isWellFormedToken(token)) {
      return null;
    }

    const result = await db.query(
      `
        SELECT
          r.identifier_hash,
          r.user_id,
          r.scope,
          r.expiry,
          r.extension_count,
          u.username,
          u.account_status
        FROM recovery_sessions r
        JOIN users u
          ON u.user_id = r.user_id
        WHERE r.identifier_hash = $1
          AND r.scope = $2
          AND r.expiry > NOW()
          AND u.account_status =
            'RECOVERY_REQUIRED'
      `,
      [
        hashToken(token),
        RECOVERY_SCOPE,
      ],
    );

    return result.rows[0] ?? null;
  }
}