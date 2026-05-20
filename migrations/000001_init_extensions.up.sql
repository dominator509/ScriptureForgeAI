-- Enable necessary PostgreSQL extensions

-- Required for secure ID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Required for semantic AI matching capabilities and HNSW indexes
CREATE EXTENSION IF NOT EXISTS "vector";
