import { Router } from "express";
import {
  register,
  verifyPasswordFactor,
} from "../controllers/auth.controller.js";
import {
  verifyTOTPLogin,
} from "../controllers/totp.controller.js";
import {
  requireJsonRequest,
} from "../middleware/session.middleware.js";

const router = Router();

router.post("/register", register);
router.post("/password", verifyPasswordFactor);

// Second factor of login. Authenticated by the MFA_PENDING
// cookie, so it requires application/json (CSRF defense).
router.post("/totp", requireJsonRequest, verifyTOTPLogin);

export default router;
