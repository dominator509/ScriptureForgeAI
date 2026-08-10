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
- Journals must stay ciphertext-only at transport and persistence boundaries; pass no plaintext or passphrases to backend routes.
- Live rooms rely on authenticated membership + JWT claims plus allowed origin checks.
- Rust gRPC service calls use mTLS plus a shared secret and verified tenant metadata in staging/production; local plaintext fallback is development-only. Rust liveness is HTTP `/healthz` on `9102` because Kubernetes gRPC probes cannot present client certificates.
- AI and Zoom paths are expected to fail closed/degrade with explicit typed errors and auditability.
- Dependency status: web PostCSS/nanoid and mobile leaf overrides are patched; mobile DRR-002 remains an open high-severity Expo/Metro `image-size` audit blocker because the available forced fix downgrades the Expo 56 lane.

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
- Mobile dependency closure requires a patched Expo 56-compatible Metro/image-size line or a deliberately tested Expo migration; see `security/dependency_risk_register.md#DRR-002`.
