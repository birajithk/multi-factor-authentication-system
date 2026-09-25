import crypto from 'crypto';
import db from '../config/database.js';

export class SecurityLogger {
    /**
     * Log a security event
     * @param {Object} eventData
     * @param {string} eventData.event_type
     * @param {string} eventData.outcome
     * @param {string} [eventData.user_id]
     * @param {string} [eventData.correlation_id]
     */
    static async logEvent({ event_type, outcome, user_id = null, correlation_id = null }) {
        // Exclude secrets: explicitly only mapping what is requested.
        const event_id = crypto.randomUUID();
        const utc_timestamp = new Date().toISOString();

        const query = `
            INSERT INTO security_events (event_id, user_id, event_type, utc_timestamp, outcome, correlation_id)
            VALUES ($1, $2, $3, $4, $5, $6)
        `;

        try {
            await db.query(query, [event_id, user_id, event_type, utc_timestamp, outcome, correlation_id]);
        } catch (error) {
            console.error('Failed to log security event:', error);
        }
    }

    /**
     * Run cleanup task for 30-day event retention
     */
    static async cleanupOldEvents() {
        const query = `
            DELETE FROM security_events
            WHERE utc_timestamp < NOW() - INTERVAL '30 days'
        `;

        try {
            const result = await db.query(query);
            console.log(`Cleaned up ${result.rowCount} old security events.`);
        } catch (error) {
            console.error('Failed to clean up old security events:', error);
        }
    }
}
