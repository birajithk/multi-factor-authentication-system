-- ============================================================
-- SecureByte MFA Database Schema
-- ============================================================

-- ============================================================
-- 1. USERS
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,

    account_status VARCHAR(30) NOT NULL DEFAULT 'ENROLLING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_account_status_check
        CHECK (
            account_status IN (
                'ENROLLING',
                'ACTIVE',
                'RECOVERY_REQUIRED',
                'DISABLED'
            )
        )
);


-- ============================================================
-- 2. TOTP CREDENTIALS
-- ============================================================

CREATE TABLE IF NOT EXISTS totp_credentials (
    user_id UUID PRIMARY KEY,

    encrypted_secret TEXT NOT NULL,
    nonce TEXT NOT NULL,
    auth_tag TEXT NOT NULL,

    key_id VARCHAR(100) NOT NULL,

    -- Last TOTP time-step that was successfully accepted.
    -- Used to prevent replay of an already accepted code.
    last_accepted_step BIGINT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_totp_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);


-- ============================================================
-- 3. PENDING MFA AUTHENTICATION
-- ============================================================

CREATE TABLE IF NOT EXISTS pending_auth (
    transaction_id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,

    failed_attempts INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_pending_auth_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    CONSTRAINT pending_auth_failed_attempts_check
        CHECK (failed_attempts >= 0)
);


-- ============================================================
-- 4. ACTIVE SESSIONS
-- ============================================================

CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,

    CONSTRAINT fk_session_user
        FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE
);


-- ============================================================
-- INDEXES
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_pending_auth_user_id
    ON pending_auth(user_id);

CREATE INDEX IF NOT EXISTS idx_pending_auth_expires_at
    ON pending_auth(expires_at);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);

-- ============================================================
-- CASE-INSENSITIVE USERNAME UNIQUENESS
-- ============================================================

-- Usernames are treated as case-insensitive by SecureByte.
-- The application stores normalized lowercase usernames, and
-- this index ensures the database also rejects case variants.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_normalized_unique
    ON users (LOWER(username));