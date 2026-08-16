# ARCHITECTURE.md

> Implementation note, 2026-06-26: remediation is targeting the repo-current stack (`go.mod` toolchain Go 1.24.3, `web/package.json` Next.js 16.2.12, React 19.2.3) while preserving the architecture's `/api/v1/*` public route direction. Older version targets in this document remain aspirational until a dedicated upgrade PR changes the manifests.

## 1. Product Summary
ScriptureForge AI (alternatively known as BibleStudyOS or ScriptureFlow) is a production-grade, multi-tenant, cloud-native Bible Study Operating System and Mobile Ecosystem. It resolves the core market gap between complex, academic desktop applications (e.g., Logos, Accordance) and overly simplistic consumer reading apps (e.g., YouVersion). 

The platform provides a unified ecosystem delivering:
*   **Trustworthy, Citation-First AI Insights:** AI generation that strictly references primary theological data sources, commentaries, lexicons, and Scripture coordinates with transparent denominational/doctrinal guardrails.
*   **Synchronized Live Bible Study Rooms:** A real-time, collaborative hybrid study canvas featuring native deep integrations with video conferencing platforms (primarily Zoom) to unify text analysis, group interaction, attendance tracking, and prayer management on a single interface.
*   **Sermon-to-Discipleship Content Pipelines:** Automated asynchronous workflows translating primary teaching outlines/transcripts into multi-channel micro-devotionals, youth lessons, and participant discussion guides.

---

## 2. Core Product Vision
The long-term vision of ScriptureForge AI is to serve as the definitive decentralized software layer for biblical education, collaborative study, and organizational workflow automation in church networks and academic institutions. 

To achieve this, the architecture implements a decoupled, highly concurrent engine capable of handling high transactions-per-second (TPS)—particularly around real-time synchronization during active study windows—while enforcing immutable audit logs for AI-generated outputs. The technical layout directly guarantees that scaling to millions of concurrent requests will not compromise isolation boundaries, user data privacy, or data integrity.

---

## 3. Target Users

```
+---------------------------------------------------------------------------------+
|                               PERMISSION MATRIX                                 |
+----------------------+--------------------+-------------------------------------+
| Role                 | Privilege Level    | System Boundary Scope               |
+----------------------+--------------------+-------------------------------------+
| Everyday Believer    | `User`             | Read-only global library, read/write|
|                      |                    | personal journals, read/write personal|
|                      |                    | prayer requests. Participant room   |
|                      |                    | access features.                    |
+----------------------+--------------------+-------------------------------------+
| Small Group Leader   | `Moderator`        | Create/manage group workspaces,     |
|                      |                    | generate group guides, launch       |
|                      |                    | Live Rooms, view aggregated group   |
|                      |                    | attendance and shared prayer logs.  |
+----------------------+--------------------+-------------------------------------+
| Pastor / Teacher     | `Author`           | Full sermon workspace privileges,   |
|                      |                    | advanced lexicon tools, structural  |
|                      |                    | content repurposing, curriculum     |
|                      |                    | creation systems.                   |
+----------------------+--------------------+-------------------------------------+
| Church Administrator | `Tenant_Admin`     | Organization-wide configuration,    |
|                      |                    | doctrinal profile lockouts, billing,|
|                      |                    | bulk member provisioning, custom    |
|                      |                    | resource shelf whitelist settings.  |
+----------------------+--------------------+-------------------------------------+
| System Administrator | `Super_Admin`      | Global platform diagnostics, infrastructure|
|                      |                    | telemetry, global tenant routing,    |
|                      |                    | security audit enforcement.        |
+----------------------+--------------------+-------------------------------------+
```

---

## 4. Key Use Cases & Workflows

### 4.1 AI-Driven Multi-Tier Study Generation
*   **Actor:** Small Group Leader (`Moderator`).
*   **Flow:** The user selects a text segment (e.g., *James 1:2–8*), identifies the audience target (*Youth*), specifies a runtime constraint (*45 minutes*), and sets the theological filter (*Evangelical*). 
*   **Execution:** The backend RAG pipeline queries the semantic database vector space, builds an isolated structural context package, feeds it to the LLM orchestrator alongside absolute system guardrails, and outputs matching synchronized structures: opening prayers, participant handouts, private leader notes, contextual breakdowns, and localized discussion questions.

### 4.2 Synchronized Live Study Room Execution with Third-Party Video
*   **Actor:** Small Group Leader (`Host`), Multiple Believers (`Participants`).
*   **Flow:** Host triggers a scheduled "Live Room" session. 
*   **Execution:** The system connects via secure WebSockets to a dedicated state coordinator while firing API webhooks to spin up/bind an active Zoom conference. The participant screen realigns dynamically: text changes, focus highlights, and revealed discussion items push out via real-time payloads. At the conclusion of the session, participant presence counters write directly to an immutable ledger, and user prayer boards freeze and archive.

### 4.3 Automated Sermon Discipleship Repurposing
*   **Actor:** Pastor (`Author`).
*   **Flow:** Pastor drops a text transcript or raw markdown sermon layout into the Sermon Workspace.
*   **Execution:** An asynchronous processing worker chunks the content, validates the textual integrity against canonical scripture blocks, and pipes queries through specialized multi-agent subroutines to extract core arguments. The system saves 5 discrete daily devotionals, a parent-child discussion template, a matching small group question pack, and a semantic tag map directly into the tenant's global asset distribution library.

---

## 5. Feature Architecture

### 5.1 Authentication, Account & Workspace Management
*   **Purpose:** Multi-tenant credential tracking, organization boundaries, and session token provisioning.
*   **Core Responsibilities:** Processing security tokens, validating JWT signatures with short lifespans (15 minutes) coupled with database-backed opaque refresh tokens, and enforcing logical isolation using strict Postgres row-level security (RLS).
*   **Main API Routes:**
    *   `POST /api/v1/auth/register`
    *   `POST /api/v1/auth/login`
    *   `POST /api/v1/auth/refresh`
    *   `POST /api/v1/auth/logout`
    *   `POST /api/v1/auth/mfa/verify`
    *   `POST /api/v1/auth/mfa/enroll`
    *   `POST /api/v1/workspaces/switch`
    *   `POST /api/auth/register` (compatibility alias)
    *   `POST /api/auth/login` (compatibility alias)
*   **Data Entities:** `User`, `Organization`, `Workspace`, `Session`, `RefreshToken`.
*   **Security Considerations:** Cryptographic salt hashing via Argon2id. Multi-factor authentication (MFA) via TOTP protocols is structurally mandatory for `Tenant_Admin` and `Super_Admin` actors. JWT validation is fail-closed to the issuer's HS256 algorithm and `scriptureforge-platform` issuer, and rejects empty user, organization, or role identity claims before downstream authorization.
*   **Client Session Lifecycle:** Web and mobile clients keep the short-lived JWT in a session bridge and perform one shared refresh-token rotation on `401` responses. Browser access JWTs are memory-only; reload bootstrap exchanges the HttpOnly, SameSite=Strict `/api` refresh cookie with `credentials: include` and never persists either token. Mobile retains the JSON body-token compatibility flow. Both clients surface `requires_mfa` challenges without storing an empty session and clear the session only when refresh rotation is rejected. Every API request has a configurable 1-120 second deadline (15 seconds by default), propagates caller cancellation, and reports timeout as a typed network fault.
*   **Failure Modes & Logic Risks:** Tenant bleeding (cross-tenant visibility via corrupted workspace session swapping). Mitigation involves appending `organization_id` implicitly to all database queries via an authenticated context wrapper, completely isolating it from direct client parameters. The authenticated organization context must be validated as a UUID before setting transaction-local `app.current_org_id` for Postgres RLS. Production RLS evidence must preserve a structured manifest proof of exact tenant table names plus same-tenant-visible, cross-tenant-hidden, and write-denied outcomes for every tenant-scoped table.

### 5.2 Role-Based Access Control (RBAC) & Permissions
*   **Purpose:** Granular data verification engine ensuring exact feature execution based on user clearance levels.
*   **Core Responsibilities:** Evaluate runtime access requests against explicit resource scopes (e.g., `workspace:guides:write`).
*   **Main API Routes:** Internal middleware assertion engine.
*   **Data Entities:** `Role`, `Permission`, `UserRoleAssignment`.
*   **Security Considerations:** Deny-by-default logic architecture. Every database read, mutation, or socket channel subscription intercepts a bitmask comparison check.
*   **Failure Modes & Logic Risks:** Privilege escalation via parameter manipulation. This is countered by relying exclusively on cryptographically signed, immutable server-side JWT claims containing the primary account permissions.

### 5.3 ScriptureForge AI Core (Orchestration Engine)
*   **Purpose:** Secure, deterministic retrieval-augmented generation engine producing zero-hallucination studies and content assets.
*   **Core Responsibilities:** Pre-processing user prompts, building structural vector index vectors via embedding pipelines, compiling source citation pathways, and verifying downstream data profiles before execution.
*   **Main API Routes:**
    *   `POST /api/v1/ai/generate/study`
    *   (Planned) `POST /api/v1/ai/generate/devotional`
    *   (Planned) `POST /api/v1/ai/ask`
*   **Data Entities:** `AIRequestLog`, `TheologicalProfile`, `CitationTrail`, `GeneratedAsset`.
*   **Security Considerations:** Malicious prompt injection filtering, strict egress scanning to prevent generation of unauthorized content profiles, and semantic tracing vectors.
*   **Provider Boundary:** Embedding and Rust vector-search failures are fail-closed typed `503` faults with sanitized client messages. Production constructors always use the configured embedding provider; offline tests inject an explicit local function and never activate a synthetic runtime vector. Rust `ProcessTextEmbedding` accepts only a provider-generated finite 1536-dimensional vector, persists it idempotently under transaction-local `app.current_org_id` RLS, and rejects requests that omit the real vector.
*   **Failure Modes & Logic Risks:** Hallucinated data parameters masking as factual biblical source references. Countermeasures involve enforcing an isolated matching system that maps LLM outputs against a fixed SQL database index of standard biblical metadata (lexicons, verses) via standard regex/deterministic matches. Any citation failing the verification step drops the output confidence level instantly to zero and triggers a system fault block.

### 5.4 Live Bible Study Rooms (Real-time Sync & Integration)
*   **Purpose:** Coordinate high-frequency real-time event distribution and application state tracking for synchronous studies.
*   **Core Responsibilities:** Manage active state objects for all live instances, process client socket pipelines, interface with meeting APIs, and distribute dynamic structural changes across clients.
*   **Main API Routes & Endpoints:**
    *   `GET /api/v1/rooms/active`
    *   `POST /api/v1/rooms/create`
    *   `WSS /api/v1/rooms/stream/{room_id}`
    *   `GET /api/v1/rooms/state/{room_id}`
    *   `POST /api/webhooks/zoom`
*   **Data Entities:** `LiveRoom`, `RoomParticipant`, `RealtimeStateEvent`, `AttendanceLog`.
*   **Security Considerations:** Token authorization occurs inside the initial WebSocket upgrade handshake using the `scriptureforge-bearer` subprotocol (`Sec-WebSocket-Protocol: scriptureforge-bearer, <short-lived-access-jwt>`); query-string credentials are rejected because intermediaries commonly log URLs. Socket identifiers must match active database user accounts. `ALLOWED_WS_ORIGINS` is required in staging and production; if it is missing under `DEPLOYMENT_ENVIRONMENT=staging|production|prod`, WebSocket upgrades fail closed instead of accepting localhost/no-origin fallbacks.
*   **Client Recovery:** Web and mobile room clients reconnect the canonical WSS stream with bounded exponential backoff and poll `GET /api/v1/rooms/state/{room_id}` while disconnected; rotated access tokens trigger a stream replacement through the session bridge.
*   **Failure Modes & Logic Risks:** State race conditions (multiple users updating fields or chat states concurrently). Mitigation relies on processing mutations through single-threaded Redis Lua scripts, achieving lockstep linear event tracking. The same Lua transaction stores the latest event and publishes an origin-tagged envelope on `room:{room_id}:events`; each API replica subscribes only while it has local room clients, suppresses its own publication, and fans out remote events through the local hub. Local broadcast remains a bounded fallback if the pub/sub path is unavailable. WebSocket ingress strictly decodes the minimal event envelope and rejects unknown fields, missing/null payloads, and client-supplied sequence values before Redis append or broadcast. If room creation commits to PostgreSQL but Redis active-state initialization fails, the API returns a sanitized `503` and applies a tenant-RLS-scoped compensation update marking the durable room inactive, with telemetry for both outcomes. Production evidence for live rooms must prove authenticated WSS load, contiguous Redis sequencing, reconnect behavior, and HTTP polling fallback against the same staged room state, with separate artifacts for replica distribution, reconnect, polling fallback, and Redis telemetry proof; polling fallback evidence must preserve the parsed artifact `latest_sequence` as structured `ws_polling_artifact_latest_sequence` matching the run's maximum accepted sequence.
*   **Zoom Webhook Mapping:** After HMAC and timestamp verification, the webhook resolves `meeting_external_id` through a transaction-local `live_rooms` lookup. It sets a valid non-tenant sentinel `app.current_org_id` to keep the base RLS policy fail-closed, then sets `app.webhook_lookup_verified=true` and the exact meeting ID; a dedicated SELECT policy permits only that bounded mapping. Mapping failures return `503` and leave the delivery unprocessed for retry, while unknown meetings remain acknowledged without state mutation.

---

## 6. Recommended Tech Stack

### 6.1 Backend API Layer & Core Business Services
*   **Technology:** **Go (Golang 1.24.3 target)**
*   **Justification:** Go establishes memory-safe data allocation models, guarantees stellar multi-threaded concurrent performance through native lightweight green threads (goroutines), and provides low baseline latency numbers without complex runtime overhead. It ensures predictable performance profile under heavy WebSocket communication flows.

### 6.2 Scripture Engine & Morphological Processor
*   **Technology:** **Rust (Stable 2026)**
*   **Justification:** Complex lexical calculations, original language morphology mapping, lemma tracking, and text parsing require direct CPU micro-optimization and compile-time memory safety bounds. Rust modules communicate natively with Go business layers over highly optimized gRPC channels using Protocol Buffers.

### 6.3 Front-End Web Application (Workspace Center)
*   **Technology:** **Next.js 16 (App Router with TypeScript)**
*   **Justification:** Next.js establishes flawless Server-Side Rendering (SSR) engines optimizing initial load pipelines for complex biblical textual frameworks. TypeScript prevents typing corruption within large application state boundaries.

### 6.4 Mobile Client Companion
*   **Technology:** **React Native via Expo Architecture**
*   **Justification:** Enables code-reuse patterns across the web and mobile layers for cross-platform components (e.g., Live Room views, state pipes) while maintaining fluid interaction speeds over native UI layouts.

### 6.5 Persistence & Data Layout Layer
*   **Database:** **PostgreSQL 17+** with the **pgvector** module extension activated.
*   **Caching & State Cache Engine:** **Redis 7.4+**
*   **Justification:** PostgreSQL manages core entity mappings with rigorous transactional safety rules (ACID compliance) and row-level protection filters. `pgvector` drives our internal multi-dimensional semantic search and theological data tracking indexes. Redis stores ephemeral state models for active Live Rooms, orchestrates the pub/sub event distribution lines, and controls global API rate-limiting blocks. Auth login additionally applies a hashed account-scoped throttle derived from normalized organization ID plus email, so credential spraying cannot bypass controls by rotating client IPs and limiter metrics do not expose account identifiers.

---

## 7. System Architecture Overview

```mermaid
graph TD
    %% Client Tier
    WebClient[Next.js 16 Web Workspace Client] -->|HTTPS / WSS| Gateway[Envoy API Gateway / Proxy Layer]
    MobileClient[React Native Companion App] -->|HTTPS / WSS| Gateway

    %% Gateway Layer
    Gateway -->|Rate Limited Operations| AuthMiddleware{Auth Verification Engine}
    
    %% Service Infrastructure Tier (Go Core)
    AuthMiddleware -->|Validated Scope Token| CoreAPI[Go Core Monolithic Microservice]
    AuthMiddleware -->|WebSocket Upgrades| LiveSync[Go WebSocket Synchronization Worker]
    
    %% Compute / AI Engine Tier
    CoreAPI -->|gRPC Parsing Engine| ScriptureRust[Rust Scripture Parsing Service]
    CoreAPI -->|RAG Extraction Pipe| AIOrchestrator[Go Multi-Agent AI Orchestrator]
    
    %% Synchronization Infrastructure
    LiveSync -->|Pub/Sub State Signals| RedisCluster[(Redis State Cache & PubSub Cluster)]
    LiveSync -->|Binds Platform Lifecycles| ZoomPlatform[Zoom OAuth & Webhook Platform API]

    %% Storage Core
    ScriptureRust -->|Read Text Indexes| PostgresDB[(PostgreSQL Primary Engine)]
    AIOrchestrator -->|Vector Embedding Lookups| PostgresDB
    CoreAPI -->|Write Mutations / Logs| PostgresDB
    
    classDef focus fill:#f9f,stroke:#333,stroke-width:2px;
    class AIOrchestrator,LiveSync focus;
```

---

## 8. External Integrations & API Adapters

The system isolates third-party entities behind tightly declared, strongly-typed domain interfaces. Concrete instances handle transport layouts, data transformations, and payload abstractions.

```go
package adapters

import (
	"context"
	"time"
)

type MeetingMetadata struct {
	MeetingID   string    `json:"meeting_id"`
	JoinURL     string    `json:"join_url"`
	StartToken  string    `json:"start_token,omitempty"`
	Passcode    string    `json:"passcode"`
	ScheduledAt time.Time `json:"scheduled_at"`
}

type AttendanceRecord struct {
	UserID    string        `json:"user_id"`
	Duration  time.Duration `json:"duration"`
	JoinedAt  time.Time     `json:"joined_at"`
	LeftAt    time.Time     `json:"left_at"`
}

// MeetingAdapter dictates full system compliance for integrated conference runtimes
type MeetingAdapter interface {
	CreateMeeting(ctx context.Context, title string, startTime time.Time, duration int) (*MeetingMetadata, error)
	FetchAttendance(ctx context.Context, meetingID string) ([]AttendanceRecord, error)
	TerminateMeeting(ctx context.Context, meetingID string) error
}
```

### Error Normalization and Fail-Safe Rules
1.  **Circuit Breaking:** All integrations use an internal circuit breaker framework. If calls to Zoom drop below a 90% success rate within a sliding window of 60 seconds, the engine trips the breaker.
2.  **Graceful Degradation:** When the circuit breaker trips, the system gracefully degrades. Instead of blocking operations, it pivots to an "Offline/In-Person" configuration mode, generating structured fallback links that allow manual conference connection paths.
3.  **Timeout Enforcement:** Network execution windows are bounded strictly at `3500ms`. Any integration thread hanging past this threshold is explicitly killed via context manipulation.
4.  **Response Boundaries:** Zoom OAuth and JSON API responses are capped at 1 MiB before decoding; malformed or incomplete meeting responses fail closed to the offline fallback, and provider error bodies are never copied into application errors.

---

## 9. Advanced Security Architecture

### 9.1 Threat Model & Boundary Designations
*   **Trust Boundary Alpha (Client to Gateway):** Untrusted data footprint. Assumes all parameters, tokens, and payloads are explicitly hostile. Sanitization captures incoming streams.
*   **Trust Boundary Beta (Internal Micro-network Services):** The repository implements mTLS server/client configuration, shared-secret authorization, and tenant metadata binding for Go-to-Rust gRPC calls. Local tests cover the handshake and request guards; cross-namespace certificate issuance, secret injection, rotation, and deployed traffic proof remain staging gates.

### 9.2 Zero-Knowledge Client Journal Architecture
To ensure ironclad security for sensitive spiritual reflections, journals utilize client-side cryptographic derivation:
1.  During system enrollment, a 256-bit passphrase key is derived on-device from user credentials using **PBKDF2** with 600,000 iterations and a dynamic unique salt configuration. The backend salt identifier is derived from tenant/user scope with a dedicated `JOURNAL_SALT_SECRET`, never the JWT signing key.
2.  Data content segments undergo symmetric encryption inside the client memory sandbox via **AES-256-GCM** prior to network transmit.
3.  The backend persistence engine processes the ciphertext stream as an opaque binary large object (BLOB). The application servers never hold the primary encryption keys.

### 9.3 Theological Filter Isolation and Prompt Safety
The RAG pipeline enforces structural prompt isolation to eliminate model poisoning and target manipulation:

```
[User Base Query Input] 
           │
           ▼
[Sanitization Filter Layer: Removes structural escape vectors, injection flags]
           │
           ▼
[Dynamic Context Compilation Block]
  ├─ Vector DB Context: Inject verbatim text segments
  ├─ Tenant Profile Parameters: Inject absolute doctrine structures (e.g., Reformed)
  └─ Safety Anchors: "Do not deviate from provided source citation bounds"
           │
           ▼
[LLM Execution Sandbox Engine]
```

---

## 10. Database Architecture

```
                       +-------------------------+
                       |      organizations      |
                       +-------------------------+
                       | PK | id (UUID)          |
                       |    | name               |
                       |    | created_at         |
                       +-------------------------+
                                    │
                                    └───┐
                                        ▼
+-----------------------+      +-------------------------+      +-------------------------+
|     scripture_texts   |      |          users          |      |       live_rooms        |
+-----------------------+      +-------------------------+      +-------------------------+
| PK | id (UUID)        |      | PK | id (UUID)          |      | PK | id (UUID)          |
| FK | organization_id  |◄────┐| FK | organization_id    |◄────┐| FK | organization_id    |
| UK | book/chapter/    |     │|    | email              |     │| FK | host_user_id       |
|    | verse per org    |     │|    | password_hash      |     │|    | title              |
|    | content          |     │|    | role               |     │|    | meeting_metadata   |
|    | embedding        |     │+-------------------------+     │+-------------------------+
+-----------------------+     │             │                  │             │
           ▲                  │             ▼                  │             ▼
           │                  │+-------------------------+     │+-------------------------+
           │                  │|    journal_entries      |     │|    room_participants    |
           │                  │+-------------------------+     │+-------------------------+
           └────────────────規┼| PK | id (UUID)          |     └| PK | id (BIGSERIAL)     |
                              | FK | user_id             |      | FK | room_id            |
                              |    | ciphertext/iv       |      | FK | user_id            |
                              |    | salt_id/version     |      |    | joined_at          |
                              +--------------------------+      |                         |
                                                                +-------------------------+
```

### PostgreSQL DDL Generation Matrix

```sql
-- Core Extension Activation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";

-- Multi-Tenant Structural Foundations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

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

-- Scripture runtime shape (mirrors migrations/000002_core_schema.up.sql)
CREATE TABLE scripture_texts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    book VARCHAR(100) NOT NULL,
    chapter INT NOT NULL,
    verse INT NOT NULL,
    content TEXT NOT NULL,
    embedding vector(1536),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_verse_index UNIQUE (organization_id, book, chapter, verse)
);

CREATE INDEX idx_scripture_vector ON scripture_texts USING hnsw (embedding vector_cosine_ops);
CREATE INDEX idx_scripture_coords ON scripture_texts (organization_id, book, chapter, verse);

-- Live Collaborative Space Schema
CREATE TABLE live_rooms (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_user_id UUID NOT NULL REFERENCES users(id),
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

-- Performance Database Index Layouts
CREATE INDEX idx_users_org ON users(organization_id);
CREATE INDEX idx_rooms_lookup ON live_rooms(organization_id, is_active);
CREATE INDEX idx_participants_lookup ON room_participants(room_id, user_id);
```

---

## 11. API Architecture

### 11.1 Route Strategy and Structure

#### Group 0: Service Health (`/live`, `/ready`)
*   `GET /live`: Process liveness only; returns `200` while the HTTP server is running.
*   `GET /ready`: Checks PostgreSQL and Redis, then in staging/production/prod performs a bounded standard gRPC health check for `scriptureforge.engine.ScriptureEngine`; unavailable or non-serving Rust readiness returns `503` without exposing transport details. During graceful shutdown it returns sanitized `503 {"status":"unready","reason":"server_draining"}` before dependency checks. Local development keeps the existing database/Redis readiness behavior so AI can remain explicitly degraded while the service is started without the engine.
*   **HTTP transport guardrails:** The API server uses validated bounded read-header, read, write, and idle deadlines plus a finite maximum header size. Ordinary `/api/` handlers receive a validated `API_REQUEST_TIMEOUT_MS` context deadline (15 seconds by default, 1-120 seconds allowed) so database/cache/provider work ends with the client request, while WebSocket handlers replace the upgraded connection’s deadlines with their own bounded ping/read/write policy after hijacking the connection. Structured auth, journal, AI, and room-create JSON payloads reject unknown/trailing fields and use bounded bodies; room-create requests are capped at 16 KiB with 256-byte titles. Shutdown uses a validated `SHUTDOWN_TIMEOUT_MS` budget (10 seconds by default, 1-120 seconds allowed), marks readiness draining, rejects new room upgrades, and closes tracked room streams before dependency cleanup.
*   **Tenant list failure handling:** Active-room and journal list queries keep their transaction-local RLS context and check `pgx.Rows.Err()` after iteration; mid-stream database failures return generic `500` faults with dependency telemetry rather than truncated successful lists.
*   **Dependency startup/pool guardrails:** PostgreSQL and Redis startup probes share a bounded dependency timeout; pgx and go-redis pool sizes, wait/dial/read/write timeouts, and PostgreSQL connection lifetimes are explicit environment-driven values with Terraform validation. Startup fails closed when dependencies do not respond within the configured bound.
*   **Browser boundary guardrails:** `ALLOWED_WS_ORIGINS` is also the API’s credentialed CORS allowlist. Strict environments reject missing, non-HTTPS, private, or placeholder origins at startup; disallowed origins and unknown preflight headers receive `403`, while API responses apply `nosniff`, frame, referrer, permissions, CSP, HSTS, and no-store controls. Browser unsafe mutations bootstrap `GET /api/v1/auth/csrf` and must submit the readable SameSite=Strict token cookie with a matching `X-CSRF-Token` header; native callers are not subject to the browser double-submit check.

#### Group A: Authentication & Provisioning (`/api/v1/auth`)
*   `GET /api/v1/auth/csrf`: Issue or reuse the browser-readable SameSite=Strict CSRF token cookie for credentialed unsafe web requests.
*   `POST /api/v1/auth/login`: Issue verification challenges. Returns a short-lived JWT and, for web clients, sets an HttpOnly, SameSite=Strict refresh-token cookie scoped to `/api`.
*   `POST /api/v1/auth/register`: Provision member accounts with tenant-bound role defaults.
*   `POST /api/v1/auth/refresh`: Exchange an active refresh token from the web cookie or compatibility request body for a rotated access/refresh pair; web responses omit the refresh token body.
*   `POST /api/v1/auth/logout`: Revoke an issued refresh token.
*   `POST /api/v1/auth/mfa/verify`: Process real-time dynamic authentication codes.
*   `POST /api/v1/auth/mfa/enroll`: Provision a TOTP seed for privileged roles.
*   `POST /api/v1/workspaces/switch`: Switch organization context on signed-in sessions.
*   Compatibility aliases: `POST /api/auth/register`, `POST /api/auth/login` (same handler/validation behavior as canonical routes).

#### Group B: AI Generation Engine Pipeline (`/api/v1/ai`)
*   `POST /api/v1/ai/generate/study`: Generate curriculum tracks.
*   Compatibility alias: `POST /api/ai/curriculum` (delegates to the same generation handler).
    *   Generation fails closed with a typed `503` when required RAG, verification, LLM, MapReduce, database, or AI audit persistence dependencies are unavailable; successful or failed attempts are not served without an audit write.
    *   Readiness includes the RAG vector database and nonblank LLM API key, endpoint, model, and bounded HTTP client; direct RAG/LLM calls also return typed configuration faults when their dependency graph is incomplete.
    *   Aggregate curriculum assembly uses amortized buffering with an 8 MiB response envelope across the bounded chunk set; overflow is audit-recorded as a failed attempt and returns a typed `503` without serving partial output.
    *   LLM network, malformed-response, and empty-response faults use sanitized typed errors; provider URLs, transport messages, and response bodies are not returned to callers.
    *   MapReduce uses UTF-8-safe bounded chunks and a capped worker pool with cancellation-aware scheduling; invalid processors and canceled work fail closed without unbounded goroutine fan-out.
    *   *Payload Structure:*
        ```json
        {
          "passage_coordinates": {
            "book_number": 59,
            "chapter": 1,
            "verse_start": 2,
            "verse_end": 8
          },
          "target_audience": "youth",
          "runtime_minutes": 45,
          "theological_lens": "reformed"
        }
        
```
    *   *Response Signatures:* High integrity JSON data blocks featuring a standard `citation_trail` block containing absolute database IDs linked directly to source documents.

#### Group C: Real-Time Synchronization Socket Endpoints (`/api/v1/rooms`)
*   `POST /api/v1/rooms/create`: Initialize dynamic tracking matrices.
*   `GET /api/v1/rooms/active`: Query structural context instances running under the client tenant signature.
*   `GET /api/v1/rooms/state/{room_id}`: Poll latest room event payload for reconnect/fallback clients.
*   `WSS /api/v1/rooms/stream/{room_id}`: Broadcast real-time room events after membership and tenant validation.

#### Group D: System Webhooks (`/api/webhooks`)
*   `POST /api/webhooks/zoom`: Validate signed Zoom webhook callbacks and map meeting lifecycle events to internal room state transitions.

#### Group E: Journal Endpoints (`/api/v1/journal`)
*   `GET /api/v1/journal/bootstrap`: Resolve tenant/user scoped journal salt material for client-side encryption keys.
*   `POST /api/v1/journal_entries`: Persist encrypted journal payload fragments.
*   `GET /api/v1/journal_entries`: List encrypted journal entries for authenticated user.
*   `GET /api/v1/journal_entries/{id}`: Fetch a single encrypted journal entry.

---

## 12. Frontend / Client Architecture

### 12.1 State Domain Management Strategy
The web and mobile frameworks partition client-side information states cleanly to eliminate view inconsistencies:
*   **Server Cached Mirror State:** Driven by `@tanstack/react-query`. Captures, invalidates, and mirrors persistent backend structures (e.g., resource catalog entries, profile parameters).
*   **Ephemeral Presentation UI State:** Driven by localized `Zustand` instances. Tracks structural client presentation values (e.g., viewport splitting coordinates, translation comparison panels, current accessibility font sizing modifiers).
*   **Real-time Collaborative Sync Canvas:** Driven by highly reliable WebSocket pipelines hooked directly to React Context layers. Captures remote state adjustments and maps them down to local UI surfaces with zero interference to focus points.
*   **Session and Recovery Boundary:** Zustand-backed session bridges keep access tokens in memory and update rotated values atomically for client requests; browser refresh custody remains in the HttpOnly cookie while mobile retains body-token compatibility. Room views use the canonical WSS stream and authenticated polling fallback, while native-device and deployed-browser behavior remains a staging validation responsibility.

### 12.2 User Interface Progressive Disclosure Strategy
To accommodate both novice users and advanced researchers, structural UI visibility adapts dynamically based on the active display mode configuration:

```
[User Selects Layout Configuration Profile]
   │
   ├─► Beginner Mode ───► Hide Commentary Panels, Disable Linguistic Lexicons, Show Single Stream Text
   │
   ├─► Leader Mode ─────► Split Layout Viewport, Reveal Dynamic Host Controls, Enable Live Question Overlays
   │
   └─► Scholar Mode ────► Activate Reverse Interlinear Views, Map Strong's Coordinate Identifiers, Pin Vector Heatmaps
```

---

## 13. Error Handling, Reliability, and Failure Modes

### 13.1 Universal Structural Taxonomy
Application logic threads surface exceptions using an explicit, strongly typed system architecture instead of passing ambiguous error codes.

```go
package errors

type ErrorCategory string

const (
	CategoryTransient ErrorCategory = "TRANSIENT_NETWORK_FAULT"
	CategoryData      ErrorCategory = "DATA_VALIDATION_INTEGRITY_VIOLATION"
	CategorySecurity  ErrorCategory = "SECURITY_AUTHORIZATION_DENIAL"
	CategoryAIModel   ErrorCategory = "AI_ORCHESTRATION_ENGINE_FAULT"
)

type PlatformException struct {
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
	Code     int           `json:"code"`
	TraceID  string        `json:"trace_id"`
}

func (e *PlatformException) Error() string {
	return e.Message
}
```

### 13.2 Graceful System Degradation Paths
*   **Scenario A: Total AI Provider Outage.** The system blocks prompt interface execution, displays a service disruption message to the user, and shifts to a deterministic local template engine. Users remain fully capable of reading static texts, browsing pre-computed commentaries, and modifying local journals.
*   **Scenario B: Socket Synchronization Channel Collapse.** If live streaming disconnects, the mobile companion drops down gracefully to a standard poll pattern over HTTPS interfaces every 10 seconds. Real-time active indicators shift visually from green to orange to alert room hosts without interrupting structural display layouts.

---

## 14. Testing Architecture

Implementations must construct and evaluate code changes against a four-tier automated testing strategy. Every code commit requires testing to ensure functionality before code submission.

### 14.1 Test Profile Framework Configurations

#### Tier Alpha: Strict Unit Coverage Matrix
*   Targeting core isolated mathematical transformations, access control evaluations, and syntax conversion pipelines.
*   *Enforcement Rules:* Zero external socket operations allowed. Memory mocks replace database states. Minimum threshold set at **90% coverage lines**.

#### Tier Beta: Integration Pipeline Integration Tests
*   Verify cross-system data updates. Execute sequential test suites targeting PostgreSQL database interaction, verify row-level security boundaries, and evaluate Redis caching lines.

#### Tier Gamma: Automated Red-Team Security Tests
*   Execution targets fuzzing parameters on entry fields to detect SQL injection attempts, testing token tampering vectors across tenancy limits, and verifying prompt escape constraints.

### 14.2 Core Testing Strategy (Execution Prompt Blueprint)
```text
[MASTER AGENT PROMPT: AUTOMATED SECURITY AND VALIDATION TEST GENERATION]
COMMAND: Scan the current target domain layer code under directory /internal/domain/auth.
TASK: Generate localized system tests handling the following functional scenarios:
  1. Deny invalid JWT access claims completely.
  2. Block workspace mutation parameters if tenant_id cross-references fail to validate.
  3. Validate cryptographic boundaries when malicious payloads pass through string variables.
REQUIREMENT: Ensure all test cases compile flawlessly without dependencies on external networks.
```

---

## 15. Upgradeability and Maintainability

### 15.1 Production Folder Layout Strategy (Hexagonal Clean Architecture)

```text
/
├── cmd/
│   └── platform-engine/        # Core System Entrypoint Binaries
├── internal/
│   ├── domain/                 # Pure Immutable Enterprise Business Entities
│   │   ├── auth/
│   │   ├── bible/
│   │   └── room/
│   ├── ports/                  # Inbound/Outbound Interface Abstraction Handlers
│   │   ├── driving_http.go
│   │   └── driven_db.go
│   └── adapters/               # Concrete Technology Implementation Infrastructure
│       ├── database_postgres/
│       ├── cache_redis/
│       └── integration_zoom/
├── pkg/                        # Universal Shareable System Utilities
│   └── crypto_utils/
├── proto/                      # Core Language-Agnostic Interface Definitions
├── web/                        # Next.js Production Web Project Workspace
└── mobile/                     # React Native App Client Workspace
```

<h3>15.2 Database Version Upgrades Strategy</h3>
*   No structural changes may occur directly within running database consoles. All data changes are driven exclusively by explicit linear migration files parsed through a file migration tool (`golang-migrate`).
*   Migration logic scripts must supply balanced down steps for every up operation. Schema mutations must adhere to a backward-compatible format, allowing legacy production clusters to operate smoothly alongside pending software updates during canary release cycles.

---

## 16. Deployment & CI/CD Architecture

```
[Developer / Code Agent Commit]
              │
              ▼
[CI Verification Gate (GitHub Actions Cluster)]
  ├─ Audit Dependency Analysis (Trivy Verification)
  ├─ Code Compilation & Strict Type Assessment
  └─ Concurrent Test Execution Matrix (Unit & Integration)
              │
              ▼
[Container Construction Pipeline]
  └─ Build Minimal OCI Distroless Container Architecture
              │
              ▼
[Staging Deployment Verification Step]
              │
              ▼
[Production Canopy Release Swap (ArgoCD Control Engine)]
  └─ Progressive Routing Shift: 1% -> 10% -> 50% -> 100%
```

The staging deployment verification step must attach real Terraform and Kubernetes artifacts through `tools/deploymentprobe`. `DEPLOY-TF-001` and `DEPLOY-K8S-001` evidence is accepted only when probe summaries carry both verified deployment markers and `staging artifact` provenance; Terraform approval fallback evidence must include a structured `change_ticket=<ticket-id>` marker when it substitutes for apply output, and strict-release validation rejects approval summaries that omit that ticket ID. Mock, placeholder, synthetic, stubbed, test-only, dry-run, localhost, or loopback artifacts are treated as non-production evidence.

### 16.1 Infrastructure Configuration Framework (Terraform Plan Abstract)
```hcl
# Core Persistent Deployment Layout
resource "aws_eks_cluster" "platform_kubernetes_core" {
  name     = "scriptureforge-production-cluster"
  role_arn = aws_iam_role.kubernetes_core_execution_iam_role.arn

  vpc_config {
    subnet_ids              = [aws_subnet.private_alpha.id, aws_subnet.private_beta.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }
}

resource "aws_rds_cluster" "storage_backend_postgres" {
  cluster_identifier      = "scriptureforge-core-postgres-cluster"
  engine                  = "postgres"
  engine_version          = "17.2"
  database_name           = "scriptureforge_prod"
  master_username         = "forge_admin_root"
  master_password         = var.database_root_security_passphrase
  storage_encrypted       = true
  deletion_protection     = true
}
```

---

## 17. Observability and Analytics

### 17.1 Telemetry Implementation Design
*   **Distributed Trace Integration:** OpenTelemetry instrumentation spans intercept every business method execution path. Trace headers propagate across external service barriers via standard context mappings (`X-Trace-ID`), logging exact database durations, parsing latencies, and third-party call dependencies. Production observability evidence must use real 32-character non-zero lowercase hex OpenTelemetry trace IDs, not placeholder correlation strings.
*   **Metric Instrumentation Profiles:** Core components expose diagnostic metrics to tracking systems at standard `/metrics` ports.
    *   `http_requests_total{status, route}`: Monitor active system traffic velocities.
    *   `websocket_active_connections_count`: Monitor synchronized system load levels.
    *   `ai_inference_duration_seconds{profile}`: Monitor real-time generative latency curves.
*   **System Log Architecture:** Structured JSON logging parameters map to all operations via standard logging libraries (`uber-go/zap`), enforcing precise field properties (`timestamp`, `severity`, `trace_id`, `tenant_id`, `component`, `message`).

---

## 18. Build Risk Register

### 18.1 LLM Token Envelope Limits & Structural Context Blinding
*   **Risk:** When long reference documents or multiple complex commentaries are appended during a deep sermon repurposing flow, user context envelopes risk overflow, resulting in dropped tokens or loss of text coherence.
*   **Mitigation Strategy:** Implement a MapReduce chunking engine. Long transcripts undergo recursive semantic distillation and summarization phases, and text nodes are organized into structural metadata pools before final payload delivery.

### 18.2 WebSocket Connection Overloads During Church Synchronization Windows
*   **Risk:** Sudden spikes in web traffic (e.g., thousands of group members joining synchronized live rooms at precisely 7:00 PM on a Wednesday) can trigger thread starvation and socket drops.
*   **Mitigation Strategy:** Offload initial room creation and member authorizations to stateless standard HTTP instances. WebSockets handle only minimal operational events. Live synchronization nodes execute in isolated autoscale groups, running load distribution thresholds managed by specialized load balancers.

---

## 19. Production Readiness Checklist

- [ ] Row-Level Security (RLS) policies are active and verified across all PostgreSQL tables, with structured staging manifest proof for every tenant-scoped table outcome.
- [ ] Database storage components apply static encryption using AWS KMS keys.
- [ ] Production API endpoints score an A+ ranking under SSL Labs cryptographic evaluations.
- [ ] Load testing profiles confirm sustainable performance at 5,000 requests per second while keeping P99 latency figures below 200ms, with WebSocket evidence also proving authenticated WSS origin behavior, Redis sequence ordering, reconnect behavior, HTTP polling fallback whose structured artifact latest sequence matches the run maximum sequence, and distinct replica/reconnect/polling/Redis telemetry artifacts.
- [ ] Zero-Knowledge client encryption tests show clean client memory space teardowns without tracking key fragments in background processes.
- [ ] Automated rate limit policies reject requests when traffic limits pass design parameters.
- [ ] OpenTelemetry dashboards successfully trace transactions across all service layers.

---

## 20. Implementation Guardrails

*   **RULE 1:** Execute comprehensive security, concurrency, and boundary tests before finalizing any architectural or codebase modules.
*   **RULE 2:** Maintain strict type safety and memory safety across all domains. The use of unsafe code pointer arrays or implicit empty target definitions (`interface{}` in Go, `any` in TypeScript) is strictly blocked unless explicitly documented.
*   **RULE 3:** Always inspect existing files, data structures, and service interfaces for context before modifying or generating new code elements to prevent code duplication or design divergence.
*   **RULE 4:** Never hard-code production secrets, security certificates, encryption keys, or tenant context parameters. Configuration values must resolve from secure environment injection points.
*   **RULE 5:** Ensure all automated commits represent small atomic blocks of functionality, pass all local integration testing checks, and do not introduce database version regressions.
*   **RULE 6:** Maintain this `ARCHITECTURE.md` file as the ultimate source of truth for the codebase, updating structural specifications immediately whenever authorized scope shifts occur.
