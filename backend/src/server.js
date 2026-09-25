import "dotenv/config";
import app from "./app.js";
import { SecurityLogger } from "./services/security-logger.service.js";

const PORT = process.env.PORT || 5000;

// Schedule security event retention cleanup (every 24 hours)
setInterval(() => {
    SecurityLogger.cleanupOldEvents().catch(console.error);
}, 24 * 60 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`SecureByte backend running on port ${PORT}`);
});