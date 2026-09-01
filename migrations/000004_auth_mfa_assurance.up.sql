ALTER TABLE refresh_tokens
    ADD COLUMN mfa_verified_at TIMESTAMPTZ;

CREATE INDEX idx_refresh_tokens_mfa_verified_at ON refresh_tokens(mfa_verified_at)
    WHERE mfa_verified_at IS NOT NULL;
