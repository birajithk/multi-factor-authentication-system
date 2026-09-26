import "dotenv/config";
import app from "./app.js";
import { SecurityLogger } from "./services/security-logger.service.js";

const PORT = process.env.PORT || 5000;

const SECURITY_EVENT_CLEANUP_INTERVAL_MS = 24 * 60 * 60 * 1000;

// Run once at startup, then schedule every 24 hours.
SecurityLogger.cleanupOldEvents().catch(console.error);
const cleanupTimer = setInterval(() => {
    SecurityLogger.cleanupOldEvents().catch(console.error);
}, SECURITY_EVENT_CLEANUP_INTERVAL_MS);
cleanupTimer.unref();

app.listen(PORT, () => {
  console.log(`SecureByte backend running on port ${PORT}`);
});