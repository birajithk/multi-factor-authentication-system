import { RecoveryService } from '../services/recovery.service.js';

export const generateCodes = async (req, res) => {
    try {
        // Assume user_id is injected by authentication middleware (e.g., req.user.user_id)
        const userId = req.user?.user_id;
        if (!userId) {
            return res.status(401).json({ success: false, error: { type: 'UNAUTHORIZED' } });
        }

        const codes = await RecoveryService.generateRecoveryCodes(userId);
        
        return res.status(200).json({
            success: true,
            data: {
                recoveryCodes: codes
            }
        });
    } catch (error) {
        console.error('Error in generateCodes:', error);
        return res.status(500).json({ success: false, error: { type: 'INTERNAL_ERROR' } });
    }
};

export const consumeCode = async (req, res) => {
    try {
        const { recoveryCode } = req.body;
        const userId = req.user?.user_id;

        if (!userId) {
            return res.status(401).json({ success: false, error: { type: 'UNAUTHORIZED' } });
        }
        if (typeof recoveryCode !== 'string' || recoveryCode.trim().length === 0) {
            return res.status(400).json({ success: false, error: { type: 'VALIDATION_ERROR', message: 'Recovery code is required' } });
        }

        const sessionHash = await RecoveryService.consumeRecoveryCode(userId, recoveryCode);
        if (!sessionHash) {
            return res.status(401).json({ success: false, error: { type: 'INVALID_CREDENTIALS', message: 'Invalid or used recovery code' } });
        }

        // Ideally, we'd set the recovery session cookie here based on sessionHash
        // For demonstration, we'll return it in the payload.
        res.cookie('recovery_session', sessionHash, {
            httpOnly: true,
            secure: true,
            sameSite: 'Lax',
            maxAge: 5 * 60 * 1000 // 5 minutes
        });

        return res.status(200).json({
            success: true,
            message: 'Recovery authorized. Please setup new authenticator.'
        });
    } catch (error) {
        console.error('Error in consumeCode:', error);
        return res.status(500).json({ success: false, error: { type: 'INTERNAL_ERROR' } });
    }
};
