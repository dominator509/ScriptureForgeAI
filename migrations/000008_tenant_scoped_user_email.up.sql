-- Email identity is scoped to the workspace that owns the user membership.
-- This preserves multi-tenant membership while avoiding a global account oracle.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_organization_email ON users(organization_id, email);
