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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
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

-- Enable Row Level Security (RLS)
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scripture_texts ENABLE ROW LEVEL SECURITY;

-- Basic RLS Policies (Assuming a generic session setup where current_setting retrieves org_id)
-- Note: Real implementation would need a secure way to set 'app.current_org_id' per session.
CREATE POLICY org_isolation_policy ON organizations
    USING (id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY user_isolation_policy ON users
    USING (organization_id = current_setting('app.current_org_id', true)::UUID);

CREATE POLICY scripture_isolation_policy ON scripture_texts
    USING (organization_id = current_setting('app.current_org_id', true)::UUID);
