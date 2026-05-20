# REGRESSION BASELINE MATRIX

## 1. Baseline Context
*   **Target:** ScriptureForge AI (BibleStudyOS) Ecosystem.
*   **Scope:** Go Core Platform Engine, Rust Scripture Engine, Next.js Web Client, React Native Mobile Client.
*   **Baseline Establishment:** This matrix establishes the immutable behavioral contract based on `SF-architecture.md` and `SF-roadmap.md`.

## 2. Core Legacy Workflows (Immutable Contracts)

### 2.1 Multi-Tenant Isolation & Authentication (Phase 2 & Architecture 5.1/5.2)
*   **Workflow:** User Authentication & RBAC via JWT.
*   **Immutable Contract:**
    *   JWT signatures must have short lifespans (15 minutes).
    *   Database-backed opaque refresh tokens are required.
    *   Strict Postgres Row-Level Security (RLS) must enforce tenant isolation (no cross-tenant visibility).
    *   Cryptographic salt hashing must use Argon2id.
    *   Deny-by-default logic architecture must be maintained. Every database read, mutation, or socket channel subscription must intercept a bitmask comparison check via signed JWT claims.
    *   Tenant `organization_id` must be appended implicitly to all database queries via an authenticated context wrapper, completely isolated from direct client parameters.

### 2.2 Zero-Knowledge Client Journal Architecture (Architecture 9.2)
*   **Workflow:** Secure storage of sensitive spiritual reflections.
*   **Immutable Contract:**
    *   256-bit passphrase key derived on-device from user credentials using PBKDF2 (600,000 iterations, unique salt).
    *   Data segments must be symmetrically encrypted inside the client memory sandbox via AES-256-GCM prior to network transmit.
    *   Backend persistence engine must process ciphertext as an opaque BLOB. Application servers must NEVER hold primary encryption keys.

### 2.3 RAG Engine & AI Orchestration (Architecture 5.3 & 9.3)
*   **Workflow:** Zero-hallucination studies and content asset generation.
*   **Immutable Contract:**
    *   RAG pipeline must query the semantic database vector space.
    *   Outputs must be checked against a fixed SQL database index of standard biblical metadata via strict regex/deterministic matches.
    *   Any citation failing the verification step drops the output confidence level to zero and triggers a system fault block.
    *   MapReduce chunking engine must be used to prevent context window overflow.
    *   Output must adhere strictly to predefined theological filter isolation to prevent model poisoning.

### 2.4 Synchronized Live Bible Study Rooms & Webhooks (Architecture 5.4)
*   **Workflow:** Real-time event distribution, state tracking, and 3rd party coordination.
*   **Immutable Contract:**
    *   Connection established via secure WebSockets (`github.com/gorilla/websocket`).
    *   Token authorization must occur inside the initial WebSocket upgrade handshake. Socket identifiers must match active database user accounts.
    *   State race conditions must be mitigated by processing mutations through single-threaded Redis Lua scripts to achieve lockstep linear event tracking.
    *   Zoom webhook integrations must validate payloads using HMAC SHA256 signature verification against `ZOOM_WEBHOOK_SECRET_TOKEN`.

### 2.5 Rust Scripture Engine (Roadmap Phase 03)
*   **Workflow:** Lexical processing and vector matching.
*   **Immutable Contract:**
    *   High-performance morphological comparison algorithms evaluating original lemmas and linguistic markers.
    *   Communication with Go business layers over highly optimized gRPC channels using Protocol Buffers.
    *   Must utilize the explicit `text_vector vector(1536)` database definition format.

## 3. Data Structures & Database Baseline
*   **Database:** PostgreSQL 17+ with `uuid-ossp` and `vector` extensions.
*   **Caching:** Redis 7.4+
*   **Schemas (Baseline Snapshots required for Differential Analysis):**
    *   `organizations`
    *   `users`
    *   `scripture_texts` (HNSW vector-cosine optimization)
    *   `live_rooms`
    *   `room_participants`
    *   `journal_entries` (encrypted payloads)
*   **Connections:** Database connection strings and credentials must use environment variables (e.g., `${DB_USER}:${DB_PASS}@${DB_HOST}/${DB_NAME}`) rather than hardcoded secrets.

## 4. Failure Handling & Degradation (Architecture 13.2)
*   **AI Outage:** Must block prompt execution, show service disruption message, and shift to a deterministic local template engine.
*   **Socket Collapse:** Must drop down gracefully to standard HTTPS polling every 10 seconds.
*   **Error Taxonomy:** Must strictly map to `PlatformException` (e.g., `TRANSIENT_NETWORK_FAULT`, `DATA_VALIDATION_INTEGRITY_VIOLATION`).
