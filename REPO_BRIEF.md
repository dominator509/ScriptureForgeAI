# ScriptureForgeAI Repo Brief

## Purpose

ScriptureForgeAI is a multi-tenant Bible study platform with authenticated workspaces, encrypted journal storage, AI-assisted study generation, live synchronized study rooms, and a production-readiness evidence pipeline.

## Stack

- Backend: Go `1.24.3` toolchain (`go 1.24.0` + `toolchain go1.24.3` in `go.mod`), PostgreSQL/pgx, Redis, Gorilla WebSocket, OpenTelemetry.
- Web: Next.js `16.2.12` + React `19.2.3` + TypeScript, Zustand.
- Mobile: Expo/React Native + TypeScript, Zustand.
- Worker/service: Rust 2021 + Tokio + Tonic gRPC.
- Infra/readiness: Terraform AWS/EKS/RDS/Redis skeleton, readiness tooling in `tools/`.

## Entrypoints

- API service: `cmd/platform-engine/main.go`
- Core handlers/routes: `internal/ports/`, `internal/domain/`
- Auth/tenant: `internal/domain/auth/`
- AI: `internal/domain/ai/`, `internal/adapters/llm/`
- Rooms/WS: `internal/domain/room/`, `internal/ports/driving_wss.go`
- Zoom: `internal/adapters/integration_zoom/`
- Rust service: `services/scripture-engine/`
- Web app: `web/src/`
- Mobile app: `mobile/src/`
- Migrations: `migrations/`

## Commands

- Bootstrap checks:
  - `node tools/verify-project-path.mjs`
  - `node tools/verify-project-path.mjs --strict-staging`
  - `node tools/run-rls-db-integration-docker.mjs`
  - The Docker RLS runner verifies daemon readiness with `docker info` and bounds Docker subprocesses; an unavailable daemon fails the gate quickly as an explicit environment blocker rather than hanging.
- Verification:
  - `go test ./...`
  - `go vet ./...`
  - `cd web && npm run smoke && npm run typecheck && npm run build`
  - `cd mobile && npm run smoke && npm run build:check`
  - `cd services/scripture-engine && cargo test --locked`
  - `go test ./tools/rustprobe -count=1`
  - `cd build/terraform && terraform fmt -check -recursive && terraform init -backend=false && terraform validate`
- Serena/Obsidian:
  - `node tools/validate-serena-obsidian.mjs`
  - `node tools/validate-roadmap-artifacts.mjs`
  - `node tools/sync-obsidian-readiness.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --expected-release-candidate replace-with-git-sha-or-tag --check`

## Important Directories

- `internal/`, `cmd/platform-engine/`, `pkg/crypto_utils/`
- `web/`, `mobile/`, `services/scripture-engine/`
- `migrations/`, `build/terraform/`, `docs/sub_roadmaps/`, `production-readiness/`, `tools/`
- `CHANGELOG.md` records durable implementation history and keeps local code evidence separate from staging proof.

## Data / Auth / External Notes

- Tenant isolation: Postgres RLS + `auth.SetTenantContext(ctx, tx, orgID)` for tenant-scoped DB access.
- Server password cryptography: `pkg/crypto_utils/password.go` owns bounded Argon2id hashing, strict stored-parameter parsing, secure salt generation, and byte cleanup; `internal/domain/auth` keeps compatibility aliases for existing handlers.
- Registration: `POST /api/v1/auth/register` and its legacy alias accept email, password, and a bounded `organization_name`; the server generates the organization UUID, inserts the organization and forced-member user in one RLS-scoped transaction, and never accepts a caller-selected tenant ID. Login/refresh/logout continue to require the returned organization ID.
- Browser sessions keep refresh tokens in an HttpOnly, SameSite=Strict `/api` cookie; access JWTs remain memory-only and reload through cookie-backed bootstrap. Mobile keeps the compatibility body-token flow, and both use short-lived access tokens with rotation. Login persists its first refresh token in the same tenant-scoped transaction as credential verification, avoiding nested pool acquisition under constrained capacity.
- Auth handlers fail closed with typed HTTP 503 dependency faults when the authentication database pool is not configured, covering registration, login, refresh, logout, and privileged MFA operations before transaction work.
- Privileged TOTP seeds are persisted only as versioned AES-GCM envelopes under the API-only `MFA_ENCRYPTION_KEY`; missing or legacy plaintext seed material fails closed until the factor is re-enrolled.
- Journals must stay ciphertext-only at transport and persistence boundaries; pass no plaintext or passphrases to backend routes. Journal writes accept only the current server-derived per-user salt ID/version returned by the authenticated bootstrap contract; mismatched versioned IDs fail before database work.
- Web and mobile journal flows list/fetch encrypted entries and decrypt only after local key derivation; mobile clears prior journal entries, plaintext, passphrase, and key handles when the user or organization changes, while access-token rotation preserves the active user's local work.
- Live rooms rely on authenticated membership + JWT claims plus allowed origin checks; room WebSocket JWTs travel in the `scriptureforge-bearer` subprotocol and query-string credentials are rejected. Validated JWTs require an expiration claim, and active room sockets close at that expiry rather than outliving the access token. Socket ingress uses a strict event envelope that rejects unknown fields, missing/null payloads, and client-supplied sequence values before an atomic Redis Lua sequence/latest-state append and pub/sub broadcast. Redis-backed room hubs subscribe per active room, suppress their own origin-tagged publication, and close subscriptions during shutdown; local hub broadcast remains the bounded fallback. Active room sockets also consume a Redis-backed leased semaphore across global, tenant, and user scopes, renew every 30 seconds, expire after two minutes without renewal, and fail closed with a sanitized `503` when Redis is unavailable. Room creation returns a sanitized `503` and marks the durable room inactive under tenant RLS if Redis active-state initialization fails after the PostgreSQL commit, preventing an unusable room from being advertised as active.
- Zoom webhooks are HMAC/timestamp verified after a dedicated public `zoom_webhook` Redis fixed-window budget and before room mapping. Mapping runs under FORCE RLS with a transaction-local non-tenant sentinel plus `app.webhook_lookup_verified=true` and an exact `meeting_external_id` policy; transient mapping failures return `503` without consuming the delivery ID so provider retries remain safe. Staging abuse proof requires `ABUSE_LIMIT_ZOOM_WEBHOOK_REQUESTS` and `ABUSE_LIMIT_ZOOM_WEBHOOK_WINDOW_SECONDS`.
- Browser boundary: `ALLOWED_WS_ORIGINS` is the shared trusted-browser origin allowlist for room upgrades and credentialed API CORS; it is required and restricted to public HTTPS origins in staging/production, while local development defaults to localhost ports 3000. Foreign origins and unsupported preflights fail closed, and API responses set no-store/security headers. Browser unsafe mutations bootstrap `GET /api/v1/auth/csrf`, then submit a readable SameSite=Strict token cookie plus matching `X-CSRF-Token`; non-browser clients retain the native compatibility path.
- Rust gRPC service calls use mTLS plus a shared secret and verified tenant metadata in every non-local deployment environment; only explicit local/development/test modes allow plaintext fallback. `ProcessTextEmbedding` requires a real provider-generated 1536-dimensional vector and atomically upserts scripture text under transaction-local tenant RLS; it never fabricates vectors. Rust liveness is HTTP `/healthz` on `9102` because Kubernetes gRPC probes cannot present client certificates. In strict staging/production environments, API `/ready` also performs a bounded standard gRPC health check for `scriptureforge.engine.ScriptureEngine` after PostgreSQL and Redis checks.
- Rust metrics/health TCP handling bounds the first request read with `RUST_ENGINE_METRICS_READ_TIMEOUT_MS` (100ms-30s, 5s default) to prevent idle connections from consuming tasks indefinitely.
- Terraform gives the API and Rust engine separate Kubernetes service accounts, IRSA roles, and SecretProviderClasses; the Rust secret set is limited to database and gRPC credentials and excludes JWT, journal, AI, and Zoom secrets.
- Staging/production runtime config requires distinct high-entropy `JWT_SECRET_KEY` and `JOURNAL_SALT_SECRET` values; journal salt derivation never falls back to the JWT signing key.
- Staging/production Go and Rust startup requires `DATABASE_URL` to use PostgreSQL `sslmode=require`, `verify-ca`, or `verify-full`; local development keeps its existing relaxed URL behavior. The Terraform example documents `sslmode=require`, but live secret contents still require staging verification.
- AI and Zoom paths fail closed/degrade with explicit typed errors and auditability; AI chat/embedding calls and decoded Zoom OAuth/meeting/status responses use bounded response bodies and retry policy, with request-body replay, cancellation-aware backoff, sanitized provider errors, and bounded MapReduce concurrency. Zoom request timeout/retry budgets are environment-driven through `ZOOM_HTTP_TIMEOUT_MS` and `ZOOM_MAX_RETRIES`, clamped to finite ranges, and Terraform projects the same bounds into the API workload. Production room creation injects the Zoom `MeetingAdapter`, persists tenant-scoped provider/external meeting identity plus safe join metadata, and never persists or returns host start URLs. AI generation requires structurally complete DB, vector, verifier, LLM configuration/HTTP, and MapReduce dependencies plus audit persistence; its aggregate curriculum uses an 8 MiB response envelope and amortized assembly, while missing configuration, oversized output, or audit writes return typed `503` faults instead of serving unaudited/partial output. Direct RAG/LLM calls fail closed on incomplete wiring.
- API transport: the Go `http.Server` applies bounded read-header (5s), read (30s), write (30s), and idle (60s) deadlines plus a 1 MiB header cap by default; ordinary `/api/` handlers also inherit a validated 15s `API_REQUEST_TIMEOUT_MS` context deadline (1-120s range), while upgraded WebSocket connections retain their handler-owned ping/read/write deadlines. Structured auth, journal, AI, and room-create JSON payloads use strict decoding and bounded bodies; room titles are capped at 256 bytes. Shutdown marks `/ready` unready before draining and closes tracked room streams within a validated 10s `SHUTDOWN_TIMEOUT_MS` budget by default.
- Tenant-scoped room and journal list handlers check `pgx.Rows.Err()` after iteration and fail closed with generic 500 responses/telemetry instead of returning truncated successful lists.
- Dependency startup/pools: API startup probes PostgreSQL and Redis with a bounded 10s dependency context; `STARTUP_DEPENDENCY_TIMEOUT_MS`, explicit pgx pool bounds/lifecycles, and Redis pool/dial/read/write bounds are validated and Terraform-projected. Defaults are 10 DB connections, 10 Redis connections, 30m DB lifetime, 5m DB idle, and no warm DB minimum.
- Redis security: non-local startup requires `REDIS_PASSWORD`; the API applies it to the parsed Redis URL/options, and Terraform sources it from the API-only runtime secret provider. Live Redis ACL, network-policy, and rotation evidence remains staging-owned.
- Abuse controls: production route wiring uses atomic Redis fixed-window request limits, including the unauthenticated public Zoom webhook `zoom_webhook` profile, and a Redis-backed leased semaphore for active room sockets, all shared across replicas. Remote identity registration is bounded with an overflow bucket, connection leases renew and expire after crashes, and unavailable Redis produces sanitized 503 fail-closed responses. The process-local limiter is retained only for explicit nil-client local/test wiring.
- Privileged MFA verification is additionally throttled by a hashed organization/user identity through the distributed `auth_account` limiter, so repeated TOTP guesses cannot bypass protection by rotating client IPs; limiter failures fail closed with sanitized responses.
- Client lifecycle: web and mobile API clients perform single-flight refresh-token rotation after expired access tokens, surface privileged MFA challenges as structured login results, reconnect room WebSockets with bounded backoff plus authenticated HTTP state polling fallback, and apply a configurable 1-120 second API request deadline (15 seconds by default) while preserving caller cancellation.
- Dependency status: web PostCSS/nanoid and mobile leaf overrides are patched; Metro now resolves the dependency-free repository-owned `mobile/vendor/image-size` compatibility package, which removes the DRR-002 high-severity audit path while `mobile/metro.config.js` keeps the affected parser and asset formats blocked.
- CI runtime status: the security workflow pins current Node24-compatible action majors for checkout, Go, Node, Terraform, and artifact upload; `tools/validate-ci-workflow.mjs` rejects a regression to legacy Node20 action majors.

## Do-Not-Touch / Risk Zones

- Do not commit `.env*`, Terraform state files, local evidence manifests, or generated caches/targets.
- Avoid editing generated protobuf outputs unless intentionally regenerating from `proto/scripture.proto`.
- Treat `node_modules`, `.next`, `dist`, `coverage`, `.gocache`, `.npm-cache`, `artifacts`, `.serena`, `.obsidian`, `.tools`, `target`, `.terraform`, `*.tfstate*`, `*.tsbuildinfo` as local-generated.
- Do not change app behavior for Serena/Obsidian setup work unless explicitly requested.

## Unknowns / TODOs

- Exact staging AWS inputs, remote state, DNS, and secret-manager dependencies are environment-owned.
- Staging must prove the Secrets Store CSI JSON shape for `grpc_engine_tls_credentials`, certificate rotation, Rust health/readiness, and Go-to-Rust mTLS/tenant binding with `tools/rustprobe`.
- Production readiness still depends on clean git sync state, pushed CI evidence, and staging proof manifests.
- Native EAS/Expo crypto behavior requires separate staged-device validation beyond local smoke checks.
- Mobile dependency closure is locally closed through the tested repository-owned image-size compatibility package; re-evaluate it on every Expo/Metro refresh and see `security/dependency_risk_register.md#DRR-002`.
