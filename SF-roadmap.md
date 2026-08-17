# BUILD_ROADMAP.md

## 1. ROADMAP SUMMARY
- This roadmap defines the comprehensive execution strategy for constructing ScriptureForge AI (BibleStudyOS), a multi-tenant, cloud-native collaborative Bible study environment.
- The platform uses a polyglot architectural design consisting of Go (Golang 1.24.3 target) for concurrent business services and real-time state synchronization, paired with a high-performance Rust service for complex original language morphological processing and lexical vector operations.
- The user-facing ecosystem delivers unified multi-device access using a Next.js 16 web core and a cross-platform React Native companion app built over Expo.
- To strictly eliminate agentic drift, logic regression, and context hallucination during autonomous code generation loops, this architecture enforces a mandatory dual-layer orchestration workflow. This roadmap requires a phase-specific sub-roadmap and synchronized Serena/Obsidian tracking before starting each phase.

## 2. EXECUTION PRINCIPLES
- **Mandatory Sub-Roadmap Generation:** Prior to executing code mutations or provisioning infrastructural files for any phase, the implementation lead must analyze the phase parameters, construct a highly localized task listing (e.g., `PHASE_01_SUB_ROADMAP.md`), and write it directly to the designated repository folder.
- **Small, Verified Patches:** Code adjustments must occur in atomic increments accompanied by localized test assets. Compilation steps and test execution blocks must pass cleanly on each incremental commit before moving to sibling tasks.
- **Strict Type Boundaries:** The use of implicit loosely typed interfaces such as `interface{}` in Go or dynamic escape types like `any` in TypeScript is strictly prohibited. Explicit data contracts, strongly typed structs, and compilation-enforced validation schemas must govern all internal network and service boundaries.
- **Fail-Safe Ingestion:** All application ingress vectors must utilize decoupled validation validation handlers (e.g., Zod schemas or strong backend validation tags) to assert parameters prior to passing structures into business modules.
- **Secret Hygiene:** Hardcoding environment details, cryptographic parameters, mock signing keys, or development credentials into the codebase is completely prohibited. All configuration values must resolve dynamically through secure ambient configuration maps or runtime injection paths.

### 2.1 Tracking Gate
- Every phase and any route/schema change must be reflected in `SF-roadmap.md`, `SF-architecture.md`, and `production-readiness/obsidian-production-readiness.md` before merge.
- Repository traceability changes must also update `CHANGELOG.md`; the changelog records implementation history separately from deployment evidence.
- `production-readiness/serena-setup.md` remains the canonical Serena bootstrap reference for cross-language indexing.
- Route additions/changes require a matching entry in `SF-architecture.md` under **11. API Architecture** before merge.
- Current dependency hardening (2026-08-10): web PostCSS/nanoid and mobile leaf overrides are patched; Metro resolves the dependency-free repository-owned `mobile/vendor/image-size` compatibility package, blocks the DRR-002 parser and asset formats, and the mobile high-severity audit is green. DRR-002 is closed locally and must be re-evaluated on every Expo/Metro refresh.
- Current CI hardening (2026-08-10): security workflow actions now use immutable pins for current Node24-compatible checkout, Go, Node, Terraform, and artifact-upload majors; workflow regression tests reject legacy Node20 action pins.
- Current exact-release CI evidence (2026-08-17): commit `c62a8f4072e999a35eed397cbea34bc523bd57e5` passed the clean `34/34` local gate matrix and hosted Security Pipeline Verification run `31995529595`; `tools/ciprobe` validated the release artifact as `SRC-CI-001`. Environment-specific staging-manifest ingestion and all deployed/staging evidence remain pending.
- Current client hardening (2026-08-10): web and mobile API clients now rotate expired access tokens through a single-flight refresh bridge, expose privileged MFA challenges without persisting empty sessions, reconnect canonical room streams with bounded backoff plus authenticated polling fallback, and enforce a configurable 1-120 second API request deadline (15 seconds by default) with typed timeout faults; client smoke/typecheck gates cover the contract while deployed browser/native staging proof remains external.
- Current mobile journal persistence hardening (2026-08-16): the mobile journal container now loads the authenticated user's encrypted entry list, fetches a selected ciphertext record through `GET /api/v1/journal_entries/{id}`, and decrypts only in local memory using the server-provided salt ID/version. Identity changes clear prior entries, plaintext, passphrase, and key handles without wiping work during ordinary access-token rotation; mobile API smoke coverage already proves encrypted list/save/load contracts, while native-device and staging evidence remain external.
- Current shared crypto boundary hardening (2026-08-16): Phase 02's planned `/pkg/crypto_utils` boundary now owns Argon2id password hashing and verification. The implementation validates work-factor ranges, bounds stored parameters before verification, uses cryptographically secure salts, clears transient byte buffers, and preserves `internal/domain/auth` compatibility aliases; focused round-trip, malformed-hash, configuration, and salt-length tests pass.
- Current auth transaction hardening (2026-08-16): successful login now inserts and commits its first opaque refresh token in the existing tenant-scoped credential transaction instead of acquiring a nested database transaction, preserving the `auth_issue_refresh_token` metric while avoiding avoidable pool exhaustion under constrained capacity; the disposable Postgres auth/session suite passes.
- Current auth dependency hardening (2026-08-17): registration, login, refresh, logout, and privileged MFA handlers now return typed HTTP 503 dependency faults when the authentication database pool is absent instead of dereferencing a nil pool; focused coverage proves the complete auth handler set fails closed.
- Current MFA assurance hardening (2026-08-17): refresh tokens persist an `mfa_verified_at` assurance timestamp, privileged refreshes require both an active factor and prior MFA proof, and privilege elevation cannot turn a member refresh token into a privileged JWT without a fresh MFA challenge. Integration coverage proves the elevation denial and verified-token assurance.
- Current MFA at-rest hardening (2026-08-17): TOTP seeds are stored as versioned AES-GCM envelopes using an API-only `MFA_ENCRYPTION_KEY`, with wrong-key, malformed-envelope, and plaintext-persistence tests; legacy plaintext rows fail closed and require re-enrollment during migration. Terraform projects the key only into the API secret provider.
- Current deployment trust-boundary hardening (2026-08-17): unknown deployment environment names now fail closed to Go/Rust gRPC mTLS and shared-secret requirements, while Terraform separates API and Rust service accounts, IRSA policies, SecretProviderClasses, and mounted secret sets. Local Terraform/runtime validators and Rust tests pass; live IAM/CSI/network evidence remains external.
- Current Redis credential hardening (2026-08-17): non-local API startup now requires `REDIS_PASSWORD`, applies it to the parsed Redis client options, and Terraform projects it from the API-only SecretProviderClass; local configuration and skeleton gates pass, while live Redis ACL/network-policy/rotation evidence remains external.
- Current journal salt binding hardening (2026-08-16): encrypted journal creation now accepts only the current server-derived per-user `journal:v1` salt ID/version from the authenticated bootstrap contract, rejects mismatched versioned salts before database work, and keeps tenant/RLS integration fixtures on that contract; focused and disposable Postgres/RLS suites pass.
- Current phase artifact gate hardening (2026-08-16): the mandatory Phase 01-06 sub-roadmaps now exist under `/docs/sub_roadmaps/`, map the original phase tasks to local evidence and external blockers, and are enforced by `tools/validate-roadmap-artifacts.mjs` in local gates and the security workflow.
- Current browser session hardening (2026-08-10): web requests identify the browser client, send credentials, and keep rotated refresh tokens in an HttpOnly SameSite=Strict cookie; access JWTs are memory-only and reload through a single-flight cookie bootstrap. Mobile and compatibility callers retain the JSON body-token flow. Backend and web smoke tests cover cookie issuance, body omission, cookie fallback, body precedence, memory-only storage, bootstrap, and rejected-cookie cleanup.
- Current JWT validation contract hardening (2026-08-16): the shared auth verifier accepts only the issuer's HS256 signing algorithm, requires the `scriptureforge-platform` issuer, and rejects tokens missing non-empty user, organization, or role claims. Focused auth tests cover alternate HMAC algorithms, issuer substitution, and missing identity claims; the existing 15-minute access-token and rotated opaque-session contract remains unchanged.
- Current AI provider hardening (2026-08-10): chat and embedding calls share bounded timeout/retry settings, rebuild request bodies on transient retries, honor cancellation during backoff, retry only 429/5xx responses, and cap provider response bodies at 1 MiB; local tests cover replay, cancellation, retry exhaustion, and oversized responses. Live provider and staging degradation evidence remains external.
- Current RAG fail-closed hardening (2026-08-10): embedding, Rust gRPC, and vector-search failures now return sanitized typed `503` faults without provider or transport details; production clients never synthesize embeddings, while offline tests inject an explicit local embedding function. Focused tests cover missing-key failure, provider-error sanitization, typed-fault preservation, and null gRPC responses.
- Current room credential hardening (2026-08-10): web and mobile room streams send the short-lived access JWT in the `scriptureforge-bearer` WebSocket subprotocol; backend middleware rejects `?ticket=` credentials and the room upgrader negotiates only the named protocol.
- Current runtime secret hardening (2026-08-10): JWT and journal salt secrets require at least 32 bytes in the shared auth policy, staging/production startup rejects missing/weak/reused values, journal bootstrap no longer falls back to `JWT_SECRET_KEY`, and Terraform/CSI/IAM wiring projects a dedicated `JOURNAL_SALT_SECRET` ARN. Cloud secret-sync and rotation evidence remains external.
- Current readiness hardening (2026-08-10): strict staging/production `/ready` now checks PostgreSQL and Redis plus a bounded standard gRPC health response for `scriptureforge.engine.ScriptureEngine`; non-serving or unreachable Rust engine state returns sanitized `503` readiness instead of allowing traffic onto a non-functional AI/RAG dependency. Local development preserves database/Redis-only readiness for explicit AI degradation.
- Current HTTP transport hardening (2026-08-10): the Go API now applies validated bounded read-header/read/write/idle deadlines and a finite header-size cap, Terraform projects the same validated settings into the API workload, environment overrides remain available for deployment tuning, and handler-owned WebSocket deadlines are preserved after upgrade.
- Current startup dependency hardening (2026-08-10): PostgreSQL and Redis startup pings now use a bounded dependency context; explicit DB pool size/lifecycle and Redis pool/dial/read/write settings replace CPU-sized or indefinite client defaults, with range validation, unit tests, and Terraform projections. Deployment tuning must keep DB minimum <= maximum and Redis active connections >= pool size.
- Current browser boundary hardening (2026-08-10): the API now validates the existing `ALLOWED_WS_ORIGINS` browser allowlist at strict-environment startup and reuses it for credentialed CORS. Foreign origins, invalid preflight methods/headers, and strict missing-origin configuration fail closed; API responses carry baseline security and no-store headers, with local native/no-origin compatibility preserved.
- Current API lifecycle hardening (2026-08-10): ordinary `/api/` handlers now inherit a validated `API_REQUEST_TIMEOUT_MS` context deadline (15 seconds by default, 1-120 seconds allowed), preserving earlier client cancellation and exempting long-lived room streams whose handler-owned deadlines begin after WebSocket upgrade. Platform cancellation tests and Terraform projection are green; deployed timeout tuning remains external.
- Current shutdown lifecycle hardening (2026-08-11): the API now marks `/ready` unready before graceful shutdown, tracks upgraded room connections, rejects new room streams while draining, closes active room sockets with a going-away signal, and uses a validated `SHUTDOWN_TIMEOUT_MS` budget (10 seconds by default, 1-120 seconds allowed). Platform and room tests pass under `-race`; deployed termination-grace and load-balancer drain behavior remains external.
- Current browser CSRF hardening (2026-08-11): credentialed web mutations now bootstrap `GET /api/v1/auth/csrf`, receive a browser-readable SameSite=Strict token cookie, and submit the matching `X-CSRF-Token` header; the API rejects missing, malformed, or mismatched browser tokens before handler execution, while native callers retain compatibility. Go security tests and web smoke cover issuance, reuse, rejection, and client bootstrap; deployed cookie/CORS behavior remains external.
- Current room ingress hardening (2026-08-11): room creation now uses the shared strict JSON decoder, rejects concatenated or unknown-field payloads, caps request bodies at 16 KiB, and rejects titles over 256 bytes before Redis or Postgres work. Focused room HTTP tests cover oversized, concatenated, and overlong inputs; deployed gateway/body-limit telemetry remains external.
- Current room event envelope hardening (2026-08-16): WebSocket room messages now use strict JSON decoding and reject unknown fields, missing/null payloads, and client-supplied sequence values before Redis append or broadcast; focused tests preserve the server-assigned sequence contract. Deployed multi-instance fan-out and load evidence remains external.
- Current room replica fan-out hardening (2026-08-16): accepted room events now use a Redis Lua append that sequences, stores latest state, and publishes an origin-tagged event atomically. Redis-backed room hubs subscribe per active room, suppress their own publication before local fallback broadcast, and close subscriptions during shutdown; focused miniredis coverage proves cross-replica delivery and cleanup. Deployed multi-replica fan-out and load evidence remains external.
- Current global abuse limiter hardening (2026-08-16): production route wiring now uses an atomic Redis fixed-window limiter shared across API replicas, bounds remote identity registration with a per-window overflow bucket, and fails closed with sanitized `503` responses when Redis is unavailable. Focused miniredis coverage proves shared windows, overflow enforcement, and backend-failure behavior; real staging ingress evidence remains `ABUSE-LIMIT-001` external.
- Current public Zoom webhook abuse hardening (2026-08-16): `/api/webhooks/zoom` now uses a dedicated unauthenticated `zoom_webhook` Redis fixed-window budget keyed by the validated client address before HMAC processing. Route tests, `tools/abuseprobe`, and strict staging evidence require `ABUSE_LIMIT_ZOOM_WEBHOOK_REQUESTS`, `ABUSE_LIMIT_ZOOM_WEBHOOK_WINDOW_SECONDS`, and `zoom_webhook=true`; real ingress proof remains `ABUSE-LIMIT-001` external.
- Current distributed room connection lease hardening (2026-08-16): active WebSocket caps now use a Redis-backed leased semaphore across global, tenant, and user scopes, with atomic Lua cleanup/acquire/renew/release, 30-second renewals, two-minute crash expiry, and sanitized `503` fail-closed behavior when Redis is unavailable. Focused miniredis coverage proves cross-instance caps, renewal, expiry recovery, and backend failure; deployed multi-replica socket-load evidence remains `PERF-WS-001` external.
- Current Rust scripture-ingestion hardening (2026-08-16): `ProcessTextEmbedding` now requires a provider-generated 1536-dimensional finite vector, validates nonempty bounded text, and atomically upserts the runtime `scripture_texts(organization_id,book,chapter,verse,content,embedding)` shape under transaction-local `app.current_org_id` RLS. Vector search uses the same tenant transaction boundary, and the Rust service refuses missing/empty `DATABASE_URL` instead of using a placeholder. Local protobuf/source gates cover the contract; deployed ingestion, RLS, and provider-backed semantic quality evidence remain external.
- Current room state initialization hardening (2026-08-16): if Redis active-state initialization fails after the durable room transaction commits, room creation returns a sanitized `503` and performs a tenant-RLS-scoped compensation update that marks the room inactive; the room is not advertised as active, and dependency telemetry records both the Redis failure and compensation outcome. DB-backed regression coverage runs in the Postgres/RLS gate; deployed multi-store failure telemetry remains external.
- Current tenant list cursor hardening (2026-08-16): tenant-scoped active-room and journal list handlers now check `pgx.Rows.Err()` after scanning and return generic `500` faults with error telemetry on mid-stream database failures instead of reporting truncated success. Existing transaction-local RLS boundaries remain unchanged; deployed database failure telemetry remains external.
- Current AI audit fail-closed hardening (2026-08-11): AI generation now requires DB, RAG, verification, LLM, and MapReduce dependencies and returns typed `503` faults when `ai_request_logs` or `citation_trails` persistence fails, preventing unaudited output. Unit tests cover missing dependencies and missing audit databases; deployed provider and audit telemetry remains external under `EXT-AI-001`.
- Current ingress type-boundary hardening (2026-08-16): shared Go JSON decoding is constrained to the allowlisted request contracts, trailing-value checks use `json.RawMessage`, and room WebSocket error responses use a typed envelope. The remaining JWT parser callback uses the upstream library's required legacy interface boundary.
- Current AI nested-readiness hardening (2026-08-16): the generation route now requires a vector database plus nonblank API key, endpoint, model, and bounded LLM HTTP client in addition to its top-level dependencies; direct RAG and LLM calls also return typed `503` configuration/search faults instead of dereferencing incomplete wiring. Focused tests cover nil and partial dependency graphs; deployed provider and audit telemetry remains external under `EXT-AI-001`.
- Current AI aggregate-output hardening (2026-08-16): generated curriculum assembly uses a `strings.Builder` with an 8 MiB aggregate envelope across the bounded MapReduce chunk set; overflow records a failed audit attempt and returns a sanitized typed `503` without serving partial output. Focused tests cover exact-limit acceptance, over-limit rejection, and nil-builder safety; deployed provider, audit, and degradation evidence remains external under `EXT-AI-001`.
- Current Zoom response/resilience hardening (2026-08-16): outbound Zoom OAuth, meeting, and status JSON responses are capped at 1 MiB before decoding; transient retries no longer drain unbounded bodies, raw provider error bodies are excluded from application errors, missing tokens/meeting fields fail closed, and malformed or oversized meeting responses use the existing offline fallback. `ZOOM_HTTP_TIMEOUT_MS` and `ZOOM_MAX_RETRIES` are environment-driven with finite 100-30000ms and 0-3 bounds, Terraform projects the same limits, and nil client wiring falls back to a finite transport. Focused adapter tests cover configuration bounds, timeout fallback, oversized responses, and missing access tokens; live Zoom evidence remains external under `EXT-ZOOM-001`.
- Current Zoom webhook RLS mapping hardening (2026-08-16): signed webhook room lookup now runs in a transaction-local context with a valid non-tenant sentinel `app.current_org_id`, `app.webhook_lookup_verified=true`, and the exact `meeting_external_id`; the dedicated `live_rooms` SELECT policy permits only that verified exact-ID lookup under FORCE RLS. Transient mapping failures return `503` without consuming the delivery ID so Zoom can retry; the DB-backed regression is part of the canonical RLS gate, while live webhook evidence remains external.
- Current LLM error-redaction hardening (2026-08-11): network, malformed-response, and empty-response failures now return sanitized typed `503` faults without provider URLs, transport details, or raw response content. Focused tests cover timeout redaction, custom transport-detail redaction, malformed responses, and empty responses; live provider evidence remains external under `EXT-AI-001`.
- Current MapReduce resource-boundary hardening (2026-08-11): AI chunking now guarantees UTF-8-safe `MaxChunkSize` bounds, and processing uses a capped worker pool with cancellation-aware scheduling plus fail-closed nil-input guards instead of one goroutine per chunk. Focused tests cover chunk limits, ordering, concurrency bounds, cancellation, and processor failures.

### 2.2 Serena/Obsidian API Drift Gate
- Route/schema changes cannot merge unless they pass `node tools/validate-serena-obsidian.mjs` in local gate and CI.
- The tool verifies canonical route coverage across runtime registration and the Obsidian/architecture tracking surfaces.
- Current canonical API surface should remain mirrored in:
  - `SF-architecture.md`
  - `production-readiness/obsidian-production-readiness.md`
  - `SF-roadmap.md`
- Canonical routes:
  - `GET /api/v1/auth/csrf`
  - `POST /api/v1/auth/register`
  - `POST /api/v1/auth/login`
  - `POST /api/auth/register` (compatibility alias)
  - `POST /api/auth/login` (compatibility alias)
  - `POST /api/v1/auth/refresh`
  - `POST /api/v1/auth/logout`
  - `POST /api/v1/auth/mfa/verify`
  - `POST /api/v1/auth/mfa/enroll`
  - `GET /api/v1/journal/bootstrap`
  - `POST /api/v1/journal_entries`
  - `GET /api/v1/journal_entries`
  - `GET /api/v1/journal_entries/{id}`
  - `POST /api/v1/ai/generate/study`
  - `POST /api/webhooks/zoom`
  - `POST /api/ai/curriculum`
  - `POST /api/v1/rooms/create`
  - `GET /api/v1/rooms/active`
  - `GET /api/v1/rooms/state/{room_id}`
  - `WSS /api/v1/rooms/stream/{room_id}`
  - `POST /api/v1/workspaces/switch`

## 3. RECOMMENDED REPOSITORY STRUCTURE
```text
/
├── docs/
│   ├── BUILD_ROADMAP.md        # Master Engineering Roadmap Architecture
│   └── sub_roadmaps/           # Directory for generated Phase-specific Task Roadmaps
├── .github/workflows/          # Production CI/CD Git Automation Workflows
├── build/                      # Container Orchestration Definitions & Deployment Configurations
│   ├── docker/                 # Minimal Multi-Stage OCI Distroless Build Templates
│   └── terraform/              # Declarative Infrastructure Configuration Framework Files
├── cmd/
│   └── platform-engine/        # Monolithic Go Business Engine Entrypoint Binary
├── internal/
│   ├── domain/                 # Pure Domain Entities & Immutable Business Rules
│   │   ├── auth/               # Multi-Tenant Token Security Domain Entities
│   │   ├── bible/              # Canonical Text Data and Structural Vectors
│   │   └── room/               # High-TPS Synchronization and State Models
│   ├── ports/                  # Inbound (Driving) and Outbound (Driven) Interface Declarations
│   │   ├── driving_http.go     # Framework Agnostic Router Port Mappings
│   │   └── driven_db.go        # Decoupled Persistence Port Layout Specifications
│   └── adapters/               # Concrete Technology Implementation Infrastructure Providers
│       ├── database_postgres/  # PostgreSQL Storage Core Driver Layer
│       ├── cache_redis/        # Redis Ephemeral High-Speed Cache Provider
│       └── integration_zoom/   # Strongly Typed Zoom API Integration Adapter Engine
├── pkg/                        # Universal Shareable Core System Utilities
│   └── crypto_utils/           # Client/Server Cryptographic Algorithms and Helpers
├── proto/                      # Language-Agnostic Protobuf RPC Interface Definitions
├── services/
│   └── scripture-engine/       # Isolated Rust Lexical and Morphological Processor Workspace
│       ├── src/                # High-Performance Text Ingestion Core Files
│       └── Cargo.toml          # Rust System Dependency Specification File
├── web/                        # Production Next.js 16 App Router Web Project Core
├── mobile/                     # React Native Mobile Companion App Expo Core Workspace
└── tests/                      # Dedicated Decoupled Universal Automated Verification Suites
    ├── unit/                   # Zero-Dependency In-Memory Business Logic Assertions
    ├── integration/            # Postgres Database and Live Cache Containerization Harnesses
    └── e2e/                    # Complete Multi-Platform System Verification Paths

5. DETAILED PHASE SPECIFICATIONS
Phase 01: Infrastructure & Data Core
• Goal: Establish the persistent multi-tenant data layer, active caching engines, and baseline infrastructure-as-code automation definitions.
• Deliverables: /docs/sub_roadmaps/PHASE_01_SUB_ROADMAP.md, declarative Terraform deployment models, atomic SQL migration files, and structural container definitions.
• Files/Folders Affected:
• /docs/sub_roadmaps/
• /build/terraform/
• /internal/adapters/database_postgres/
• migrations/
• Step-by-Step Implementation Tasks:
1.	Sub-Roadmap Generation Gate: Compile /docs/sub_roadmaps/PHASE_01_SUB_ROADMAP.md mapping tasks for schema creation, extensions configuration, and connection pooling tests.
2.	Write declarative Terraform files defining aws_eks_cluster and aws_rds_cluster setups utilizing explicit static encryption keys.
3.	Create structural database schema migration files establishing the foundational multi-tenant data boundaries, activating the uuid-ossp and vector database extensions natively.
4.	Write explicit SQL scripts defining the organizations table, the core users schema, and the performance-tuned scripture_texts data repository.
5.	Apply specialized index statements constructing HNSW vector-cosine optimization models across target column paths alongside standard coordinates tracking indices.
• Acceptance Criteria: The localized multi-tenant environment completes initialization using isolated container structures, processing full relational migrations cleanly. The core Go initialization block establishes an active pool connection to PostgreSQL and Redis, processing normal shutdowns cleanly upon receiving standard OS termination signals.
• Automated Validation & Tests: Integrate /tests/integration/db_ping_test.go confirming database pool connectivity, rollback behavior execution under standard constraint faults, and index usage validation maps.
• Security & Isolation Checks: Enforce configuration reviews proving that public ingress access vectors are entirely deactivated inside relational database configuration setups, and that database storage partitions enforce encryption parameters.
• Common Failure Modes: Proceeding to script SQL schemas without generating the local phase task map, or failing to activate the specific vector extension dependencies prior to injecting vector-typed coordinate pathways into database rows.
• Anti-Drift Notes: Do not write active business application cache operations or route handlers. Limit scope strictly to persistent storage bootstrapping and basic validation loops.
Phase 02: Auth, RBAC & Zero-Knowledge
• Goal: Author and integrate robust tenant separation filters, cryptographically sound access controls, and zero-knowledge data containment engines.
• Deliverables: /docs/sub_roadmaps/PHASE_02_SUB_ROADMAP.md, registration and authentication controllers, Argon2id encryption components, secure JWT validation engines, and client-side cryptographic derivation components.
• Files/Folders Affected:
• /docs/sub_roadmaps/
• /internal/domain/auth/
• /pkg/crypto_utils/
• /web/src/lib/crypto.ts
• Step-by-Step Implementation Tasks:
1.	Sub-Roadmap Generation Gate: Write /docs/sub_roadmaps/PHASE_02_SUB_ROADMAP.md setting micro-tasks for Argon2id hashing parameters, JWT parsing middleware, and TypeScript cryptographic derivations.
2.	Implement backend endpoint routers mapping registration parameters and session challenges, restricting parameters using validation rules.
3.	Write memory-safe string hashing modules leveraging the Argon2id derivation methodology for storage user authentication strings.
4.	Build core permission token validation wrappers issuing short-lived access structures paired with database-backed opaque tracking records.
5.	Author robust backend permission analysis middleware intercepting inbound API routing paths, implicitly mapping context requests using verified token metadata parameters to eliminate parameters vulnerability.
6.	Code browser-compliant cryptographic routines running on client layers that construct 256-bit isolation keys via PBKDF2 processing transformations using high iteration values and localized unique data salts.
7.	Develop client-side storage processing routines using AES-256-GCM algorithms to seal sensitive personal structural text transformations prior to network transmission vectors.
• Acceptance Criteria: Users register and authenticate securely across endpoint targets, receiving short-duration valid token assets. Route intercept layers deny operations failing baseline verification rules, processing parameters safely without system leaking anomalies. Personal content segments are transformed entirely into encrypted blocks prior to network ingestion.
• Automated Validation & Tests: Construct /tests/unit/auth_rbac_test.go passing corrupted signatures, expired claims, and altered tenancy identities to assert that the filtering engine denies cross-tenant request attempts. Final staging evidence must retain structured manifest proof for every tenant-scoped table showing same-tenant visibility, cross-tenant hiding, and write denial.
• Security & Isolation Checks: Enforce strict system validation confirming that the backend database cluster stores zero plain-text journal data fragments, handling incoming personal logs strictly as opaque data payload values. Login abuse controls must include both client/request throttling and hashed account-scoped throttling over normalized organization ID plus email, with low-cardinality metrics that do not expose account identifiers.
• Common Failure Modes: Extracting target tenant identities from variable client-supplied input payloads rather than pulling them from cryptographically sealed context parameters.
• Anti-Drift Notes: Ensure all encryption key generation and handling routines remain isolated in memory within client-side layers. No component may serialize plain-text decryption credentials to network interfaces.
Phase 03: Rust Scripture Engine
• Goal: Code the optimized lexical processing service to coordinate fast morphologic analysis and vector matching operations safely.
• Deliverables: /docs/sub_roadmaps/PHASE_03_SUB_ROADMAP.md, Protocol Buffer message interfaces, Rust gRPC compilation outputs, and memory-safe vector retrieval models.
• Files/Folders Affected:
• /docs/sub_roadmaps/
• /proto/scripture.proto
• /services/scripture-engine/
• Step-by-Step Implementation Tasks:
1.	Sub-Roadmap Generation Gate: Build /docs/sub_roadmaps/PHASE_03_SUB_ROADMAP.md defining specific tasks for Protobuf definitions, tonic server integration, and pgvector retrieval handlers.
2.	Author core scripture.proto contract definitions mapping structural parameters for textual queries, morphologic tracking variables, and multi-dimensional vector inputs.
3.	Initialize the dedicated Rust compilation workspace, configuring framework extensions and mapping automated gRPC code injection profiles.
4.	Build the core text handling modules in Rust executing direct retrieval procedures against target multi-tenant persistent storage infrastructures.
5.	Implement internal text ingestion routines utilizing the explicit text_vector vector(1536) database definition format.
6.	Code high-performance morphological comparison algorithms evaluating original lemmas and linguistic markers using direct CPU data allocation optimizations.
• Acceptance Criteria: The compiled Rust processing runtime initialises and accepts concurrent request interactions over local network interfaces. The core Go service successfully dispatches network requests to the Rust application container using gRPC communication lines, completing query lookups within expected performance constraints.
• Automated Validation & Tests: Integrate comprehensive memory safety test blocks inside the Rust workspace executing parallel data extraction operations against complex morphological text variations.
• Security & Isolation Checks: Go-to-Rust gRPC now requires mTLS plus a shared secret and verified organization metadata in staging/production, with bounded messages and HTTP `/healthz` probe support. Remaining work is staging certificate/secret injection, rotation, cross-namespace traffic, and captured `RUST-GRPC-001` evidence.
• Common Failure Modes: Improper handling of connection boundaries or loose string tracking blocks leading to memory fragmentation over long processing lifetimes.
• Anti-Drift Notes: Restrict the functional scope of the Rust service purely to processing original text variables and vector transformations. Do not map access management configurations or external endpoint tracking fields into the engine.
Phase 04: AI Orchestrator Pipeline
• Goal: Construct a deterministic, zero-hallucination retrieval-augmented generation engine enforcing rigid guardrails and verifiable references.
• Deliverables: /docs/sub_roadmaps/PHASE_04_SUB_ROADMAP.md, prompt validation controls, structured context compiler components, and absolute validation match tools.
• Files/Folders Affected:
• /docs/sub_roadmaps/
• /internal/domain/ai/
• /internal/adapters/llm/
• Step-by-Step Implementation Tasks:
1.	Sub-Roadmap Generation Gate: Publish /docs/sub_roadmaps/PHASE_04_SUB_ROADMAP.md detailing prompt processing, RAG assembly steps, MapReduce workflows, and citation matching regexes.
2.	Implement backend endpoint paths capturing curriculum development structures, checking incoming text configurations and filtering criteria.
3.	Create an active prompt ingestion filtering component designed to parse user inputs and completely neutralize potential text escape structures or prompt injection techniques.
4.	Write the context compilation layout engine that interacts with the semantic vector space to assemble validated resource segments.
5.	Implement explicit prompt structures binding execution engines to verified vector data boundaries, explicitly banning model output variations outside supplied citation inputs.
6.	Code a response verification match subsystem that extracts text references from model outputs and matches them against reliable database coordinates using deterministic verification logic.
7.	Develop an asynchronous MapReduce chunk processing worker capable of cleanly dividing extensive textual outlines into manageable data summaries to protect context window capacities.
• Acceptance Criteria: The generation pipeline handles document inputs and returns structured response streams containing authentic citation pathways mapped to real database records. If the verification subsystem captures an unmatched reference or model halluncination, it immediately drops output score metrics and returns an explicit execution fault.
• Automated Validation & Tests: Build unit components that feed synthetic hallucinated references into the verification module to verify that the fault execution intercept triggers appropriately.
• Security & Isolation Checks: Assert that all outgoing model interactions run inside isolated network boundaries, stripping client parameters from connection frameworks to block configuration exposure.
• Common Failure Modes: Sending raw, un-summarized text dumps directly to inference targets without applying the semantic MapReduce separation system, leading to prompt truncation or context blinding.
• Anti-Drift Notes: Ensure that generation workflows match against the fixed theological profile configurations dictated by organization settings to maintain rigid denominational guardrails.
Phase 05: Live Sockets & Zoom Sync
• Goal: Build a highly concurrent real-time distribution framework handling low-latency state changes and integrated external system synchronization.
• Deliverables: /docs/sub_roadmaps/PHASE_05_SUB_ROADMAP.md, state websocket infrastructure handlers, optimized caching scripts, multi-platform runtime adapters, and meeting lifecycle webhook controllers.
• Files/Folders Affected:
• /docs/sub_roadmaps/
• /internal/domain/room/
• /internal/ports/driving_wss.go
• /internal/adapters/integration_zoom/
• Step-by-Step Implementation Tasks:
1.	Sub-Roadmap Generation Gate: Write /docs/sub_roadmaps/PHASE_05_SUB_ROADMAP.md organizing tasks for websocket connection lifecycles, single-threaded Redis Lua operations, and Zoom lifecycle state bindings.
2.	Create specialized secure websocket routing blocks that enforce authentication handshake routines prior to connection lifecycle activation.
3.	Code atomic, single-threaded Redis Lua update scripts capable of coordinating in-memory state mutations for live environments while eliminating data race conditions.
4.	Implement the explicit structural MeetingAdapter domain layout interface to map external conference orchestration requirements.
5.	Code concrete technology adapter routines managing authenticated token lookups, meeting environment creation configurations, and automated conference termination commands.
6.	Write webhook listener paths capturing data endpoints from external systems, mapping participant duration updates to database entities.
• Acceptance Criteria: The communication architecture handles thousands of simultaneous client synchronization actions over websocket paths while maintaining latency limits inside design tolerances. External orchestration adapters connect with target systems, safely handling API faults via fallback routes. Production WebSocket evidence must include authenticated WSS load, contiguous Redis sequence proof, reconnect behavior proof, and HTTP polling fallback proof against the same staged room state, with the polling artifact's structured latest sequence matching the run maximum sequence, plus distinct artifacts for replica distribution, reconnect behavior, polling fallback, and Redis telemetry.
• Automated Validation & Tests: Formulate isolated stress injection scripts firing thousands of concurrent state mutations to verify lockstep linearity, reconnect continuity, HTTP polling fallback, and circuit breaker triggers under connection faults.
• Security & Isolation Checks: Confirm that socket connection pathways continuously validate room membership parameters, instantly discarding connection targets that drop or lose access validation claims.
• Common Failure Modes: Utilizing multi-threaded in-memory variable sharing patterns across socket instances instead of passing mutations through single-threaded Redis Lua structures, resulting in data corruption under high concurrent loads.
• Anti-Drift Notes: If communication layers drop or third-party interaction APIs respond with error codes, seamlessly degrade connection tracking metrics down to automated HTTP polling structures.
Phase 06: Web & Mobile UX Assembly
• Goal: Deliver reliable, multi-device frontend presentation layers that consume active caching modules and real-time synchronization pipelines seamlessly.
• Deliverables: /docs/sub_roadmaps/PHASE_06_SUB_ROADMAP.md, server-rendered page configurations, mobile-ready component interfaces, modular client state machines, and synchronized network cache controllers.
• Files/Folders Affected:
• /docs/sub_roadmaps/
• /web/
• /mobile/
• Step-by-Step Implementation Tasks:
1.	Sub-Roadmap Generation Gate: Compile /docs/sub_roadmaps/PHASE_06_SUB_ROADMAP.md dividing tasks between Next.js server components, React Native client layers, and cryptographic sandbox environments.
2.	Establish Next.js server routing environments configured to safely manage multi-tenant layout frameworks and optimize page delivery.
3.	Create client user interface displays that alter displayed application parameters dynamically between structured presentation views based on active role configurations.
4.	Code mobile application views utilizing specialized components capable of listening to streaming socket channels without processing loops.
5.	Setup decoupled client state models using Zustand to manage local application layout options without conflicting with persistent database mirrors.
6.	Implement the local client cryptographic container logic ensuring journal isolation calculations take place strictly inside unmapped ephemeral memory boundaries.
• Acceptance Criteria: Web applications and mobile client environments compile cleanly and establish persistent connections to local socket systems. Screen layouts adapt dynamically to remote coordinator changes, rendering textual modifications and interactive parameters under correct isolation permissions.
• Automated Validation & Tests: Configure cross-platform end-to-end interface execution flows (Playwright/Detox) confirming registration tasks, room synchronization events, and multi-tenant layout isolation behavior.
• Security & Isolation Checks: Run automated memory profile scans proving that user encryption passphrases and plain-text decryption credentials vanish from client runtime scopes upon session teardown events.
• Common Failure Modes: Allowing critical workspace permission verification tasks to execute solely within client-side browser logic loops, exposing endpoint pathways to unauthorized manipulation.
• Anti-Drift Notes: Frontend modules must operate purely as reactive presentation surfaces reflecting trusted backend states. Do not implement authorization evaluation logic inside application view blocks.
### 2026-08-16 Authentication MFA Lifecycle Hardening
• Enrollment now stages a privileged user's TOTP seed with `mfa_enabled=false` and no-store response headers.
• `/api/v1/auth/mfa/verify` activates staged enrollment only after a valid code; active factors cannot be replaced through the seed endpoint without an explicit recovery design.
• Integration coverage proves staged enrollment, activation, cache policy, and active-factor replacement denial; this remains within the planned PR3 auth/session/MFA contract.

6. CODING AGENT OPERATING RULES (FOR IMPLEMENTATION LEAD)
•
• Look Before You Leap: Before executing textual changes, partial file rewrites, or code injection steps, the implementation lead must parse the target code asset and all corresponding sibling interface declarations fully to maintain consistent architectural design boundaries.
• Preserve Testing Footprints: The implementation lead must never truncate, comment out, or disable previously passing test suites or type definitions to mask compilation errors or resolve configuration mismatches.
• No Invisible Failures: Avoid catching errors using silent or unlogged catch blocks. Every logical exception must map directly to the standardized, strongly typed platform exception architecture, ensuring complete log tracing viability across systems.
• Deterministic Mocks: When building logic paths that interact with external third-party infrastructure layouts or cloud system APIs, the implementation lead must first construct a robust localized mock asset prior to building live network connectivity drivers.
7. DEFINITION OF DONE (DoD)
• Roadmap Verification: All tasks mapped within the generated Phase Sub-Roadmap must be marked complete and pass independent logic verification steps.
• Compilation Metrics: System code must compile with zero errors, static analysis linting checks must pass cleanly, and strict typing structures must be preserved across languages.
• Testing Coverage: Automated verification frameworks must demonstrate complete test coverage across updated logic vectors, core transaction pathways, and permission filters.
• Security Validation: System security configurations must confirm that row-level data segregation rules are fully active, storage partitions are encrypted, and zero unauthenticated API scopes are exposed.
• Traceability: Structural repository configuration modifications must resolve into atomic commits, completing with an update to the project's centralized CHANGELOG.md file detailing historical evolution paths.
