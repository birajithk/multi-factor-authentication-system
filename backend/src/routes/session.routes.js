import { Router } from "express";

import {
  requireFullSession,
  requireJsonRequest,
} from "../middleware/session.middleware.js";

import {
  getDashboard,
  getCurrentSession,
  logout,
  extendCurrentSession,
} from "../controllers/session.controller.js";

/*
 * Mounted at /api.
 *
 * Guards are attached per route (not router.use) so they do not
 * run for other /api routers.
 */
const router = Router();

router.get("/dashboard", requireFullSession, getDashboard);
router.get("/session", requireFullSession, getCurrentSession);

router.post(
  "/session/logout",
  requireJsonRequest,
  requireFullSession,
  logout,
);

router.post(
  "/session/extend",
  requireJsonRequest,
  requireFullSession,
  extendCurrentSession,
);

export default router;
