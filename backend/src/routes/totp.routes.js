import express from "express";

import {
    startTOTPEnrollment,
    verifyTOTPEnrollment,
    verifyTOTPLogin
} from "../controllers/totp.controller.js";

const router = express.Router();

router.post(
    "/enroll",
    startTOTPEnrollment
);

router.post(
    "/enroll/verify",
    verifyTOTPEnrollment
);

router.post(
    "/verify-login",
    verifyTOTPLogin
);

export default router;