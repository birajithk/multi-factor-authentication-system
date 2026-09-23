import express from "express";

import {
    startTOTPEnrollment,
    verifyTOTPEnrollment
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

export default router;