export const requireFullAuth = (req, res, next) => {
    // Placeholder for actual full-session/enrollment verification
    if (!req.user) {
        return res.status(401).json({ success: false, error: { type: 'UNAUTHORIZED' } });
    }
    next();
};

export const requirePendingAuth = (req, res, next) => {
    // Placeholder for actual pending-auth verification
    if (!req.user) {
        return res.status(401).json({ success: false, error: { type: 'UNAUTHORIZED' } });
    }
    next();
};
