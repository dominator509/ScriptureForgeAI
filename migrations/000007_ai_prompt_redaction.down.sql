-- Prompt redaction is intentionally irreversible: deleted prompt content is
-- not recoverable and must not be reintroduced by a rollback.
DO $$
BEGIN
    RAISE EXCEPTION '000007_ai_prompt_redaction is irreversible';
END $$;
