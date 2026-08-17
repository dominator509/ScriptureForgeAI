DROP INDEX IF EXISTS idx_refresh_tokens_mfa_verified_at;

ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS mfa_verified_at;
