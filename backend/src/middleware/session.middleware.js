import db from '../config/database.js';

const unauthorized = (res) => res.status(401).json({ success: false, error: { type: 'UNAUTHORIZED' } });

export const requireFullAuth = async (req, res, next) => {
    try {
        const sessionId = req.headers['x-session-id'];
        const enrollmentUserId = req.headers['x-user-id'];

        if (typeof sessionId === 'string' && sessionId.trim().length > 0) {
            const result = await db.query(`
                SELECT user_id
                FROM sessions
                WHERE session_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
            `, [sessionId]);

            if (result.rowCount > 0) {
                req.user = { user_id: result.rows[0].user_id };
                return next();
            }
        }

        if (typeof enrollmentUserId === 'string' && enrollmentUserId.trim().length > 0) {
            req.user = { user_id: enrollmentUserId.trim() };
            return next();
        }

        return unauthorized(res);
    } catch (error) {
        console.error('Error in requireFullAuth middleware:', error.message);
        return res.status(500).json({ success: false, error: { type: 'INTERNAL_ERROR' } });
    }
};

export const requirePendingAuth = async (req, res, next) => {
    try {
        const transactionId = req.headers['x-pending-auth-id'];
        if (typeof transactionId !== 'string' || transactionId.trim().length === 0) {
            return unauthorized(res);
        }

        const result = await db.query(`
            SELECT user_id
            FROM pending_auth
            WHERE transaction_id = $1 AND expires_at > NOW()
        `, [transactionId.trim()]);

        if (result.rowCount === 0) {
            return unauthorized(res);
        }

        req.user = { user_id: result.rows[0].user_id };
        return next();
    } catch (error) {
        console.error('Error in requirePendingAuth middleware:', error.message);
        return res.status(500).json({ success: false, error: { type: 'INTERNAL_ERROR' } });
    }
};
