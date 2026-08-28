DROP INDEX IF EXISTS idx_users_organization_email;
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
