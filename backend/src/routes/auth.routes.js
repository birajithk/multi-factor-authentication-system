import { Router } from "express";
import {
  register,
  verifyPasswordFactor,
} from "../controllers/auth.controller.js";

const router = Router();

router.post("/register", register);
router.post("/password", verifyPasswordFactor);

export default router;