import express from 'express';
import { generateCodes, consumeCode } from '../controllers/recovery.controller.js';
import { requireFullAuth, requirePendingAuth } from '../middleware/session.middleware.js';

const router = express.Router();

// Generate recovery codes (requires full session or enrollment session)
router.post('/generate', requireFullAuth, generateCodes);

// Consume recovery code (requires pending auth after password check)
router.post('/consume', requirePendingAuth, consumeCode);

export default router;
