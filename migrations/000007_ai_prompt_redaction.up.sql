-- AI audit rows retain status, errors, citations, and prompt size, but never
-- retain user prompt content. This migration intentionally scrubs old rows.
ALTER TABLE ai_request_logs
    ADD COLUMN prompt_length INTEGER NOT NULL DEFAULT 0;

UPDATE ai_request_logs
   SET prompt_length = octet_length(prompt),
       prompt = '[redacted]';

ALTER TABLE ai_request_logs
    ADD CONSTRAINT ai_request_logs_prompt_redacted
    CHECK (prompt = '[redacted]' AND prompt_length >= 0);
