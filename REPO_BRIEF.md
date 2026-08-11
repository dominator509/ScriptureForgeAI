# ScriptureForgeAI Repo Brief

## Purpose

ScriptureForgeAI is a multi-tenant Bible study platform with authenticated workspaces, encrypted journal storage, AI-assisted study generation, live synchronized study rooms, and a production-readiness evidence pipeline.

## Stack

- Backend: Go `1.24.3` toolchain (`go 1.24.0` + `toolchain go1.24.3` in `go.mod`), PostgreSQL/pgx, Redis, Gorilla WebSocket, OpenTelemetry.
- Web: Next.js `16.2.12` + React `19` + TypeScript, Zustand.
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
  - `node tools/sync-obsidian-readiness.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --expected-release-candidate replace-with-git-sha-or-tag --check`

## Important Directories

- `internal/`, `cmd/platform-engine/`, `pkg/crypto_utils/`
- `web/`, `mobile/`, `services/scripture-engine/`
- `migrations/`, `build/terraform/`, `production-readiness/`, `tools/`

## Data / Auth / External Notes

- Tenant isolation: Postgres RLS + `auth.SetTenantContext(ctx, tx, orgID)` for tenant-scoped DB access.
- Browser sessions keep refresh tokens in an HttpOnly, SameSite=Strict `/api` cookie; access JWTs remain memory-only and reload through cookie-backed bootstrap. Mobile keeps the compatibility body-token flow, and both use short-lived access tokens with rotation.
- Journals must stay ciphertext-only at transport and persistence boundaries; pass no plaintext or passphrases to backend routes.
- Live rooms rely on authenticated membership + JWT claims plus allowed origin checks; room WebSocket JWTs travel in the `scriptureforge-bearer` subprotocol and query-string credentials are rejected.
- Browser boundary: `ALLOWED_WS_ORIGINS` is the shared trusted-browser origin allowlist for room upgrades and credentialed API CORS; it is required and restricted to public HTTPS origins in staging/production, while local development defaults to localhost ports 3000. Foreign origins and unsupported preflights fail closed, and API responses set no-store/security headers.
- Rust gRPC service calls use mTLS plus a shared secret and verified tenant metadata in staging/production; local plaintext fallback is development-only. Rust liveness is HTTP `/healthz` on `9102` because Kubernetes gRPC probes cannot present client certificates. In strict staging/production environments, API `/ready` also performs a bounded standard gRPC health check for `scriptureforge.engine.ScriptureEngine` after PostgreSQL and Redis checks.
- Staging/production runtime config requires distinct high-entropy `JWT_SECRET_KEY` and `JOURNAL_SALT_SECRET` values; journal salt derivation never falls back to the JWT signing key.
- AI and Zoom paths fail closed/degrade with explicit typed errors and auditability; AI chat/embedding calls use bounded shared timeout/retry policy, request-body replay, cancellation-aware backoff, and a 1 MiB provider-response cap.
- API transport: the Go `http.Server` applies bounded read-header (5s), read (30s), write (30s), and idle (60s) deadlines plus a 1 MiB header cap by default; ordinary `/api/` handlers also inherit a validated 15s `API_REQUEST_TIMEOUT_MS` context deadline (1-120s range), while upgraded WebSocket connections retain their handler-owned ping/read/write deadlines. Shutdown marks `/ready` unready before draining and closes tracked room streams within a validated 10s `SHUTDOWN_TIMEOUT_MS` budget by default.
- Dependency startup/pools: API startup probes PostgreSQL and Redis with a bounded 10s dependency context; `STARTUP_DEPENDENCY_TIMEOUT_MS`, explicit pgx pool bounds/lifecycles, and Redis pool/dial/read/write bounds are validated and Terraform-projected. Defaults are 10 DB connections, 10 Redis connections, 30m DB lifetime, 5m DB idle, and no warm DB minimum.
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
