-- This security cleanup is intentionally irreversible. Legacy plaintext TOTP
-- seeds are not restored by rollback; affected users must re-enroll MFA.
DO $$
BEGIN
    RAISE EXCEPTION '000005_mfa_legacy_plaintext_cleanup is irreversible';
END $$;
