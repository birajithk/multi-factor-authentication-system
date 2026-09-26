import express from "express";

import {
    startTOTPEnrollment,
    verifyTOTPEnrollment
} from "../controllers/totp.controller.js";

import {
    requireJsonRequest
} from "../middleware/session.middleware.js";

const router = express.Router();

/*
 * Both routes are authenticated by the ENROLLMENT pending
 * cookie, so they require application/json (CSRF defense).
 */
router.post(
    "/enroll",
    requireJsonRequest,
    startTOTPEnrollment
);

router.post(
    "/enroll/verify",
    requireJsonRequest,
    verifyTOTPEnrollment
);

export default router;
