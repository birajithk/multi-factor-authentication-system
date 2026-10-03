import express from "express";

import {
  generateCodes,
  consumeCode,
  startRecoveryTOTPEnrollment,
  verifyRecoveryTOTPEnrollment,
} from "../controllers/recovery.controller.js";

import {
  requireFullAuth,
  requireMfaPending,
  requireJsonRequest,
  requireRecoverySession,
} from "../middleware/session.middleware.js";



const router = express.Router();

/*
 * Generate a fresh recovery-code set.
 *
 * Only a fully authenticated account may generate or replace
 * recovery codes.
 */
router.post(
  "/generate",
  requireJsonRequest,
  requireFullAuth,
  generateCodes,
);

/*
 * Consume one recovery code as the alternative second factor.
 *
 * Password authentication must already have produced an
 * MFA_PENDING cookie.
 */
router.post(
  "/consume",
  requireJsonRequest,
  requireMfaPending,
  consumeCode,
);

/*
 * Start replacement-authenticator enrollment.
 */
router.post(
  "/totp/enroll",
  requireJsonRequest,
  requireRecoverySession,
  startRecoveryTOTPEnrollment,
);

/*
 * Verify and activate the replacement authenticator.
 */
router.post(
  "/totp/enroll/verify",
  requireJsonRequest,
  requireRecoverySession,
  verifyRecoveryTOTPEnrollment,
);

export default router;