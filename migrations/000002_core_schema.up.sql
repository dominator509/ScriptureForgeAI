-- Core Schema Definitions with Tenant Isolation

-- Organizations Table
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    mfa_secret TEXT,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, organization_id)
);

-- Index for tenant isolation lookups
CREATE INDEX idx_users_organization_id ON users(organization_id);

-- Scripture Texts Table
CREATE TABLE scripture_texts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    book VARCHAR(100) NOT NULL,
    chapter INTEGER NOT NULL,
    verse INTEGER NOT NULL,
    content TEXT NOT NULL,
    embedding VECTOR(1536), -- Assuming OpenAI dimension sizes or similar
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Standard tracking index
CREATE INDEX idx_scripture_texts_org_book_chap_verse ON scripture_texts(organization_id, book, chapter, verse);

-- HNSW Vector-Cosine Optimization Index
CREATE INDEX idx_scripture_texts_embedding_hnsw
ON scripture_texts USING hnsw (embedding vector_cosine_ops);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    rotated_from UUID REFERENCES refresh_tokens(id),
    FOREIGN KEY (user_id, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);

CREATE TABLE journal_entries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    salt_id VARCHAR(128) NOT NULL,
    salt_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX idx_journal_entries_owner ON journal_entries(organization_id, user_id, created_at DESC);

CREATE TABLE live_rooms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_user_id UUID NOT NULL,
    title VARCHAR(255) NOT NULL,
    meeting_provider VARCHAR(64) NOT NULL DEFAULT 'offline',
    meeting_external_id VARCHAR(255),
    meeting_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, organization_id),
    FOREIGN KEY (host_user_id, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX idx_live_rooms_active ON live_rooms(organization_id, is_active, created_at DESC);
CREATE UNIQUE INDEX idx_live_rooms_meeting_external_id
ON live_rooms(meeting_external_id)
WHERE meeting_external_id IS NOT NULL;

CREATE TABLE room_participants (
    id BIGSERIAL PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    room_id UUID NOT NULL,
    user_id UUID NOT NULL,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(room_id, user_id),
    FOREIGN KEY (room_id, organization_id) REFERENCES live_rooms(id, organization_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX idx_room_participants_room ON room_participants(organization_id, room_id, user_id);

CREATE TABLE ai_request_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    prompt TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, organization_id),
    FOREIGN KEY (user_id, organization_id) REFERENCES users(id, organization_id) ON DELETE CASCADE
);

CREATE TABLE citation_trails (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ai_request_log_id UUID NOT NULL,
    citation TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ai_request_log_id, organization_id) REFERENCES ai_request_logs(id, organization_id) ON DELETE CASCADE
);

CREATE INDEX idx_ai_request_logs_org_created ON ai_request_logs(organization_id, created_at DESC);
CREATE INDEX idx_citation_trails_log ON citation_trails(ai_request_log_id);

-- Enable Row Level Security (RLS)
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE scripture_texts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scripture_texts FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE journal_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE journal_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE live_rooms ENABLE ROW LEVEL SECURITY;
ALTER TABLE live_rooms FORCE ROW LEVEL SECURITY;
ALTER TABLE room_participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE room_participants FORCE ROW LEVEL SECURITY;
ALTER TABLE ai_request_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_request_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE citation_trails ENABLE ROW LEVEL SECURITY;
ALTER TABLE citation_trails FORCE ROW LEVEL SECURITY;

-- Basic RLS Policies (Assuming a generic session setup where current_setting retrieves org_id)
-- Note: Real implementation would need a secure way to set 'app.current_org_id' per session.
CREATE POLICY org_isolation_policy ON organizations
    USING (id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY user_isolation_policy ON users
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY scripture_isolation_policy ON scripture_texts
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY refresh_token_isolation_policy ON refresh_tokens
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY journal_entry_isolation_policy ON journal_entries
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY live_room_isolation_policy ON live_rooms
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY room_participant_isolation_policy ON room_participants
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY ai_request_log_isolation_policy ON ai_request_logs
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY citation_trail_isolation_policy ON citation_trails
    USING (organization_id = current_setting('app.current_org_id', true)::UUID)
    WITH CHECK (
        organization_id = current_setting('app.current_org_id', true)::UUID
        AND
        EXISTS (
            SELECT 1
            FROM ai_request_logs
            WHERE ai_request_logs.id = citation_trails.ai_request_log_id
              AND ai_request_logs.organization_id = current_setting('app.current_org_id', true)::UUID
        )
    );
