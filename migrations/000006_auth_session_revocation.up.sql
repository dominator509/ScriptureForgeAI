-- Persist the cutoff after which previously issued access tokens and room
-- sessions must no longer be accepted for a user.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS sessions_revoked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_sessions_revoked_at
    ON users (organization_id, id)
    WHERE sessions_revoked_at IS NOT NULL;
