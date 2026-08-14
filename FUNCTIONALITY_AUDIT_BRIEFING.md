# ScriptureForgeAI Functionality Audit Briefing

Date: 2026-06-23
Auditor: Codex
Scope: production and code functionality gaps across backend, web, mobile, Rust engine, migrations, infrastructure, and local verification gates.

## Executive Summary

The repository has a useful skeletal implementation for the intended ScriptureForgeAI platform, but it is not production-ready. Several reports in the repo mark phases as complete, yet the live code still contains placeholder behavior, missing persistence paths, non-runnable verification gates, and production integration gaps.

The highest-risk gaps are:

1. Tenant isolation is not wired end-to-end. RLS policies depend on `app.current_org_id`, but application DB sessions do not set that variable.
2. Authentication is incomplete relative to the architecture. There are no refresh tokens, MFA routes, session storage, or documented `/api/v1/*` paths.
3. Live room functionality is an authenticated WebSocket echo server, not a room state synchronization system.
4. The web and mobile clients are local demos and do not perform real auth, room selection, journal persistence, API discovery, or backend environment routing.
5. Rust scripture engine tests/build are blocked by missing `protoc`.
6. Go tests cannot run in the current `cmd.exe` environment because `go` is not on PATH.
7. Web build cannot run because the `next` binary is unavailable, likely because `web/node_modules` is not installed.

## Verification Performed

- `git status --short --branch`: clean `main...origin/main` before audit.
- `rtk go test ./...`: failed immediately because `go` was not found on PATH.
- `rtk npm run build` in `web/`: failed because `next` was not recognized.
- `rtk cargo test` in `services/scripture-engine/`: dependency resolution/build started, then failed because `protoc` was missing.
- Manual source inspection of docs, backend entrypoints, ports, auth, AI, room, Zoom, migrations, web, mobile, Rust service, Terraform, and existing reports.

## Critical Gaps

### F-AUD-001: Tenant isolation RLS is not connected to application sessions

Severity: Critical
Area: database/auth/backend
Evidence:
- `migrations/000002_core_schema.up.sql` enables RLS and defines policies using `current_setting('app.current_org_id', true)::UUID`.
- The migration itself notes that a real implementation must securely set `app.current_org_id` per session.
- No inspected backend code sets `app.current_org_id` before querying.
- `tests/integration/db_ping_test.go` sets the variable manually inside a test transaction, which proves the application layer does not own the behavior.

Impact:
Production requests may fail closed under RLS or bypass intended tenant guarantees if table owners/superusers are used incorrectly. The architecture promises implicit organization scoping, but the implementation does not enforce it at the database session boundary.

Recommended fix:
Add a DB access wrapper that requires verified auth claims and runs all tenant-scoped work inside a transaction or connection context with `SET LOCAL app.current_org_id = $claims.OrganizationID`. Add integration tests that exercise actual handlers, not only manual SQL.

### F-AUD-002: Auth/session model does not match production contract

Severity: Critical
Area: auth/API
Evidence:
- `cmd/platform-engine/main.go` mounts `/api/auth/register` and `/api/auth/login`, while architecture documents `/api/v1/auth/register`, `/api/v1/auth/login`, and `/api/v1/auth/refresh`.
- `internal/ports/auth_http.go` issues access tokens with `2*time.Hour`; the architecture calls for short-lived 15-minute JWTs plus database-backed opaque refresh tokens.
- There is no refresh token table in the migration and no refresh handler.
- MFA is documented as mandatory for privileged roles, but no MFA route or TOTP implementation exists.

Impact:
The platform cannot support secure session renewal, revocation, privileged-role MFA, or the documented API contract.

Recommended fix:
Introduce `/api/v1/auth/*` routes, refresh-token persistence, revocation/rotation, short access-token TTLs, and privileged-role MFA enforcement. Keep legacy routes only as explicit compatibility aliases if needed.

### F-AUD-003: WebSocket room sync is an echo server with permissive origins

Severity: Critical
Area: live rooms/realtime/security
Evidence:
- `internal/ports/driving_wss.go` sets `CheckOrigin` to always return `true`.
- `HandleLiveRoom` upgrades the socket and echoes whatever message it receives.
- No room ID, membership check, tenant check, Redis state mutation, event schema validation, broadcast hub, reconnect handling, or polling fallback exists in the socket path.

Impact:
Live Bible Study Rooms are not functionally implemented. In production this would expose an overly permissive WebSocket endpoint that authenticates a token but does not validate room authorization or constrain origins.

Recommended fix:
Require an explicit room identifier, validate membership against tenant-scoped storage, restrict origins by environment config, validate event envelopes, route all mutations through Redis Lua/state manager, and implement broadcast/presence semantics.

### F-AUD-004: Journal encryption is local-only and uses a static salt

Severity: High
Area: web/mobile/zero-knowledge
Evidence:
- `web/src/components/JournalEditor.tsx` uses `const userSalt = "static-user-salt-12345"`.
- The save path encrypts into component state and leaves the backend `fetch('/api/journal'...)` call commented out.
- No backend journal route exists in inspected routes.
- The database migration does not include `journal_entries`, despite the architecture requiring encrypted journal persistence.

Impact:
The zero-knowledge journal is a demo, not a usable persisted feature. Static salt also weakens per-user key derivation assumptions.

Recommended fix:
Add a deterministic per-user salt strategy, backend journal ciphertext endpoints, `journal_entries` migration, tenant/user scoping, and client save/load integration tests.

### F-AUD-005: AI path depends on live external APIs and legacy model choices without robust production controls

Severity: High
Area: AI/RAG
Evidence:
- `internal/domain/ai/rag.go` calls OpenAI embeddings directly from request flow.
- `internal/adapters/llm/client.go` panics at startup when `OPENAI_API_KEY` is absent outside testing.
- The LLM request hardcodes `gpt-4`.
- HTTP clients have no explicit timeout, retry, circuit breaker, provider abstraction, rate limit handling, or audit persistence for `AIRequestLog`/`CitationTrail`.
- `ResponseVerificationSubsystem.Verify` returns success when the generated text has no citations at all.

Impact:
The production AI feature is fragile under provider outage, slow network calls, key misconfiguration, and citation-free answers. It also does not persist the immutable audit artifacts promised by the architecture.

Recommended fix:
Replace startup panic with fail-closed route readiness, configure provider/model/timeout through env, add bounded HTTP clients, persist AI request/citation logs, and require citations for routes that promise citation-first output.

### F-AUD-006: Rust scripture engine does not build in this environment

Severity: High
Area: Rust/gRPC/toolchain
Evidence:
- `rtk cargo test` failed in `services/scripture-engine`.
- Exact blocker: `Could not find protoc`; build script requires protobuf code generation.

Impact:
The scripture engine cannot be verified or rebuilt locally until protobuf compiler provisioning is added.

Recommended fix:
Document/provision `protoc`, or vendor a `protoc` source through build tooling. Add CI setup for the Rust engine and fail the pipeline if generated gRPC code cannot be rebuilt.

### F-AUD-007: Frontend build is not currently runnable

Severity: High
Area: web/build
Evidence:
- `rtk npm run build` in `web/` failed: `'next' is not recognized as an internal or external command`.
- `web/package.json` has no lint/test/typecheck scripts, only `dev`, `build`, and `start`.

Impact:
The Next app cannot be built in the audited environment, and there is no frontend verification surface beyond manual inspection.

Recommended fix:
Install/restore dependencies, add `typecheck`, `lint`, and a minimal Playwright smoke test, then make web build part of CI.

### F-AUD-008: Go backend tests are blocked by missing Go on PATH

Severity: High
Area: backend/toolchain
Evidence:
- `rtk go test ./...` failed: `Binary 'go' not found on PATH`.
- `go.mod` declares `go 1.23` and `toolchain go1.24.3`, while architecture references Go 1.26+.

Impact:
Backend correctness is not locally verified in this shell path. Existing reports that say tests are fully integrated should not be treated as current verification.

Recommended fix:
Provision Go in the shell that runs repo scripts, align docs and `go.mod` on the intended version, and run `go test ./...` with DATABASE/Redis-dependent tests clearly isolated or containerized.

## Major Gaps

### F-AUD-009: Infrastructure is placeholder Terraform, not deployable production IaC

Severity: Medium-High
Area: infrastructure
Evidence:
- `build/terraform/main.tf` contains hardcoded placeholder AWS role ARN and subnet IDs.
- RDS has `skip_final_snapshot = true` while also claiming production deletion protection.
- No modules, variables, backend state config, secrets manager integration, IAM roles, node groups, Redis, ingress, container images, or app service manifests are present.

Impact:
The repo cannot deploy the documented architecture from the included Terraform.

Recommended fix:
Replace placeholder IDs with variables/data sources, add state/backend configuration, define IAM/network/app resources, and run `terraform validate` in CI.

### F-AUD-010: Zoom integration lacks production resilience controls

Severity: Medium-High
Area: integrations
Evidence:
- `internal/adapters/integration_zoom/zoom_client.go` uses default `http.Client{}` with no timeout.
- Architecture promises 3500ms timeouts, circuit breaking, and graceful fallback, but no circuit breaker or fallback path exists.
- Webhook handler updates Redis active state by Zoom meeting ID, but no mapping to internal `live_rooms.id` was found.

Impact:
Zoom outages or slow calls can hang request paths, and webhook events may not map to the correct internal room lifecycle.

Recommended fix:
Add bounded clients, retry/circuit breaker behavior, explicit meeting-to-room mapping, fallback offline-room behavior, and webhook replay/idempotency handling.

### F-AUD-011: Mobile app is a journal demo, not the documented companion experience

Severity: Medium-High
Area: mobile
Evidence:
- `mobile/App.tsx` renders only `HomeScreen`.
- `mobile/src/screens/HomeScreen.tsx` renders `SecureJournalContainer`.
- No auth, room subscription, API client, offline state, push handling, or real backend integration was found.

Impact:
The companion app does not satisfy the room participation, authenticated workspace, or synchronized study requirements.

Recommended fix:
Add auth/session bootstrap, API configuration, room list/active-room connection, journal persistence, and Expo verification commands.

### F-AUD-012: Web app is not connected to real backend state

Severity: Medium-High
Area: web
Evidence:
- `web/src/components/layout/RoomLayout.tsx` connects to hardcoded `wss://api.scriptureforge.com/ws/room`.
- Zustand initializes `activeRoomId` as `null`, and no UI/API path was found to create or select a room.
- No login/register UI exists despite backend auth handlers.

Impact:
The dashboard cannot perform the primary workflows from the architecture.

Recommended fix:
Add environment-driven API base URLs, auth screens, room creation/listing, active room selection, and real socket event handling.

## Additional Gaps

- API versioning is inconsistent: docs use `/api/v1/*`, code uses `/api/auth/*`, `/api/ai/curriculum`, `/api/webhooks/zoom`, and `/ws/room`.
- Database schema differs from architecture: docs define `doctrinal_profile`, `live_rooms`, `room_participants`, and `journal_entries`; migration only includes `organizations`, `users`, and `scripture_texts`.
- `scripture_texts` schema differs between docs and code: docs use translation/book_number/text_content/text_vector; migration/code use organization_id/book/content/embedding.
- The architecture requires audit logs and telemetry; no OpenTelemetry, structured logger, `/metrics`, trace IDs, or persistent audit-log tables were found in the inspected implementation.
- Existing `FUNCTIONAL_COVERAGE_REPORT.md` and `audit_report.txt` overstate completion relative to current runnable evidence.

## Recommended Next Work Sequence

1. Restore runnable local gates: Go on PATH, `web/node_modules`, `protoc`, and a clean Rust build.
2. Fix tenant DB session scoping and add handler-level RLS integration tests.
3. Normalize API routes to `/api/v1/*` and implement refresh-token-backed auth.
4. Replace the WebSocket echo path with room authorization, event schemas, Redis mutation, and broadcast behavior.
5. Add journal persistence end-to-end with per-user salts and encrypted payload storage.
6. Convert web/mobile demos into backend-integrated flows.
7. Replace placeholder Terraform and add CI workflows that run backend, web, and Rust gates.

## Remediation Tracker

Status last updated: 2026-06-23

- F-AUD-001: In progress. Tenant-scoped handlers now use `auth.SetTenantContext` for journal, room, AI audit, registration, login, refresh-token rotation, logout, and MFA writes. Handler-level DB tests still need a runnable Go/Postgres environment.
- F-AUD-002: In progress. Canonical `/api/v1/auth/*` routes, 15-minute access tokens, refresh rotation, logout, privileged-role TOTP enforcement, and organization-scoped login/refresh/logout payloads have been added.
- F-AUD-003: In progress. The echo WebSocket has been replaced with room membership checks, configured origin validation, JSON room events, Redis-backed latest-state persistence, and membership-gated HTTP room polling/listing.
- F-AUD-004: In progress. Backend encrypted journal endpoints and web/mobile API integration have been added; mobile still needs a production-grade native AES-GCM binding beyond the existing Expo structural placeholder.
- F-AUD-005: In progress. AI startup no longer panics on missing API keys, model/endpoint/timeout settings are environment-driven, citation-free outputs fail verification, and AI request/citation audit rows are persisted.
- F-AUD-006: External blocker. CI and docs now provision `protoc`; local verification still depends on `protoc` being installed on the active shell path.
- F-AUD-007: In progress. Web `typecheck` script and CI install/build gates have been added; local verification still depends on `web/node_modules`.
- F-AUD-008: External blocker. CI now targets Go `1.24.3`; local verification still depends on Go being available in the active shell path.
- F-AUD-009: In progress. Terraform placeholders were replaced with a variable-driven validated skeleton for EKS/RDS/Redis boundaries.
- F-AUD-010: In progress. Zoom now uses bounded HTTP calls, circuit-breaker state, offline meeting fallback, and webhook meeting-to-room lookup.
- F-AUD-011: In progress. Mobile now uses environment-driven API config, register/login bootstrap, authenticated encrypted journal saves, and room list/create/select screens; production-grade native AES-GCM remains a follow-up beyond the existing Expo structural placeholder.
- F-AUD-012: In progress. Web now has minimal auth bootstrap, room create/list/select, environment-driven WS config, and journal persistence integration.

## Current Production Readiness Verdict

Not production-ready. The codebase has useful foundations and several security-aware components, but the primary product workflows are incomplete and current local validation does not pass.
