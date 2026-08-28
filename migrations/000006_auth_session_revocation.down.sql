DROP INDEX IF EXISTS idx_users_sessions_revoked_at;

ALTER TABLE users
    DROP COLUMN IF EXISTS sessions_revoked_at;
