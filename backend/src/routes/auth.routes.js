import { Router } from "express";
import {
  register,
  verifyPasswordFactor,
  logout
} from "../controllers/auth.controller.js";

const router = Router();

router.post("/register", register);
router.post("/password", verifyPasswordFactor);
router.post("/logout", logout);

export default router;