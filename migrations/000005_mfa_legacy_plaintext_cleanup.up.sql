-- Legacy deployments may contain plaintext TOTP seeds in mfa_secret.
-- Do not attempt to migrate the seed through SQL: the application key is not
-- available to the database migration and plaintext must not be re-exposed.
-- Clearing the legacy value and disabling MFA forces a fresh enrollment.
UPDATE users
SET mfa_secret = NULL,
    mfa_enabled = FALSE,
    updated_at = CURRENT_TIMESTAMP
WHERE mfa_secret IS NOT NULL
  AND mfa_secret NOT LIKE 'v1.%';
