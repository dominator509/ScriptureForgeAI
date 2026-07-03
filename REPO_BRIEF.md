# ScriptureForgeAI Repo Brief

## Purpose

ScriptureForgeAI is a multi-tenant Bible study platform with authenticated workspaces, encrypted journal storage, AI-assisted study generation, live synchronized study rooms, and a production-readiness evidence pipeline.

## Stack

- Backend: Go `1.24.3` toolchain (`go 1.24.0` + `toolchain go1.24.3` in `go.mod`), PostgreSQL/pgx, Redis, Gorilla WebSocket, OpenTelemetry.
- Web: Next.js `16.2.9` + React `19` + TypeScript, Zustand.
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
- AI and Zoom paths are expected to fail closed/degrade with explicit typed errors and auditability.

## Do-Not-Touch / Risk Zones

- Do not commit `.env*`, Terraform state files, local evidence manifests, or generated caches/targets.
- Avoid editing generated protobuf outputs unless intentionally regenerating from `proto/scripture.proto`.
- Treat `node_modules`, `.next`, `dist`, `coverage`, `.gocache`, `.npm-cache`, `artifacts`, `.serena`, `.obsidian`, `.tools`, `target`, `.terraform`, `*.tfstate*`, `*.tsbuildinfo` as local-generated.
- Do not change app behavior for Serena/Obsidian setup work unless explicitly requested.

## Unknowns / TODOs

- Exact staging AWS inputs, remote state, DNS, and secret-manager dependencies are environment-owned.
- Production readiness still depends on clean git sync state, pushed CI evidence, and staging proof manifests.
- Native EAS/Expo crypto behavior requires separate staged-device validation beyond local smoke checks.
