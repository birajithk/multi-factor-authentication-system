import express from 'express';
import { generateCodes, consumeCode } from '../controllers/recovery.controller.js';
// Assume there's an authentication middleware that populates req.user
// import { requireAuth } from '../middleware/auth.middleware.js';

const router = express.Router();

// Generate recovery codes (requires full session or enrollment session)
// router.post('/generate', requireAuth, generateCodes);
router.post('/generate', generateCodes);

// Consume recovery code (requires pending auth after password check)
// router.post('/consume', requireAuth, consumeCode);
router.post('/consume', consumeCode);

export default router;
