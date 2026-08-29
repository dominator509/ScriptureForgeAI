# ScriptureForgeAI Production Threat Model

Status last updated: 2026-08-28

## Scope

This model covers the current repository implementation and deployment skeleton:

- Go API on port `8080`, including auth, journal, rooms, AI generation, Zoom webhooks, health, readiness, metrics, and WebSocket upgrade paths.
- Rust scripture gRPC engine on port `50051`.
- Next.js web client and Expo mobile companion.
- PostgreSQL with tenant-scoped RLS, Redis room state, AWS Secrets Manager, EKS, ALB ingress, and Terraform deployment skeleton.

This is a repo-local threat model. It does not replace staging evidence for AWS IAM, Secrets Store CSI, DNS, TLS, OTLP collector, Zoom delivery, AI provider behavior, Redis, Postgres, or Kubernetes runtime behavior.

## Trust Boundaries

| Boundary | Assets Crossing | Primary Controls |
| --- | --- | --- |
| Public browser/mobile to API | Credentials, access tokens, encrypted journal payloads, room events, AI prompts | TLS ingress skeleton, JWT verification, route auth, strict JSON decoding, abuse limits, audit logs |
| Browser/mobile to WebSocket | JWT bearer identity, room event envelopes, session state | Allowed origin checks, JWT validation, room membership and session-revocation checks, bounded frames, deadlines, ping/pong lifecycle |
| API to PostgreSQL | Tenant data, refresh tokens, journal ciphertext, AI audit rows | `auth.SetTenantContext`, transaction-scoped `app.current_org_id`, RLS, tenant-aware constraints, tenant-scoped email uniqueness, server-side refresh token hashing, HTTP/refresh session-cutoff checks |
| API to Redis | Room state and sequence counters | Redis Lua mutation path, sequence ordering tests, room membership checks before mutation |
| API to AI provider | Prompts, citations, generated content | Missing-key fail-closed behavior, bounded HTTP client, timeout/retry config, citation verification, `ai_request_logs`, `citation_trails` |
| API to Zoom | Meeting creation and webhook events | Bounded HTTP client, retry/circuit breaker, offline fallback, webhook signature verification, idempotency, meeting-to-room mapping |
| EKS workload to secrets | Database URL, JWT, OpenAI, Zoom credentials | IRSA workload service account, Secrets Store CSI skeleton, Secrets Manager ARN inputs, secret hygiene validator |
| API/Rust/web to observability | Logs, metrics, traces, trace IDs | Structured logs, `/metrics`, W3C `traceparent`, OTLP env wiring, dashboards, alerts, retention runbook |

## STRIDE Analysis

| Threat | Primary Target | Current Mitigations | Remaining Production Evidence |
| --- | --- | --- | --- |
| Spoofing | User/admin identity, WebSocket participants, Zoom webhooks | JWT claim verification, privileged-role TOTP enforcement, refresh rotation/revocation, WebSocket JWT checks, Zoom signature verification | CI artifact ingestion into the staging manifest, staging auth abuse telemetry, live Zoom webhook delivery proof |
| Tampering | Journal payloads, room events, AI citations, deployment config | Strict journal payload decoding, encrypted-only journal storage, room event envelopes, Redis Lua sequence mutation, citation verification, Terraform invariant validator | Staging Redis ordering proof, deployed config drift monitoring |
| Repudiation | Auth, AI generation, room/socket incidents, Zoom callbacks | JSON access logs with trace IDs, `/metrics`, `ai_request_logs`, `citation_trails`, webhook idempotency records | Deployed log/metric/trace retention, dashboard import, alert delivery |
| Information Disclosure | Tenant data, journal plaintext, secrets, provider responses | PostgreSQL RLS, tenant handler tests, AES-GCM client crypto, passphrase/salt byte wiping, disposable journal key handles with stale-key revocation, plaintext journal rejection, secret hygiene scanning, IRSA/CSI skeleton | Staging secret sync proof, native-device crypto validation, cloud access review |
| Denial of Service | Auth, AI, journal, rooms, WebSockets, dependencies | Configurable route/socket abuse limits with bounded identity buckets, bounded HTTP clients, WebSocket frame limits/deadlines, circuit breaker for Zoom, local load harness | Staging load test against real ingress/API/Redis/Postgres/AI, rate-limit observation under real client identity |
| Elevation of Privilege | Tenant boundaries, privileged roles, workload secret access | RLS on tenant tables, `auth.SetTenantContext`, role-forcing registration tests, privileged MFA, least-privilege Secrets Manager IAM skeleton | Staging IAM/IRSA proof, threat-model review signoff, and staging-manifest CI artifact ingestion |

## Current Security Evidence

- AI audit confidentiality: generation writes retain only a fixed redacted prompt marker and byte length in `ai_request_logs`; migration `000007_ai_prompt_redaction` scrubs historical prompt bodies, while provider-side retention remains an external control.
- Tenant isolation: `tests/integration/tenant_handler_rls_test.go` and `tests/integration/table_rls_test.go` cover same-tenant success and cross-tenant denial for handler paths and tenant tables.
- Auth/session: `tests/integration/auth_session_test.go`, `cmd/platform-engine/routes_test.go`, and `internal/domain/auth/middleware_test.go` cover canonical and legacy routes, registration role forcing, short access-token TTL, refresh rotation/revocation, user-wide HTTP/refresh logout cutoff enforcement, expired-token logout denial, dummy verification for missing users, privileged MFA, and auth abuse buckets.
- Journal confidentiality: backend journal handlers reject plaintext/passphrase fields, persist ciphertext-only entries, and deny cross-user/cross-tenant reads; `tools/verify-journal-crypto.mjs` checks AES-GCM behavior, non-extractable keys, derivation byte wiping, disposed key-handle rejection, stale raw-key revocation, and untracked-key rejection in the Node-backed mobile/web crypto harness.
- WebSocket integrity: `internal/ports/rooms_realtime_test.go`, `internal/domain/room/redis_lua_test.go`, and `tools/loadtest` cover membership-gated events, rejected invalid frames, reconnect behavior, HTTP polling, and Redis-backed ordering.
- AI safety/auditability: `internal/adapters/llm/client_test.go` and `internal/ports/ai_audit_integration_test.go` cover missing-key failure, timeouts, citation-free/hallucinated-citation rejection, and audit persistence without live provider calls.
- Zoom resilience: `internal/adapters/integration_zoom/*_test.go` covers timeouts, circuit-open fallback, signature denial, duplicate webhook safety, and meeting-to-room mapping.
- Deployment security shape: `tools/validate-deployment-skeleton.mjs`, Terraform fmt/validate, and `security/secret_handling_review.md` cover TLS ingress skeleton, remote state shape, workload secret references, IRSA/CSI wiring, default-deny Kubernetes network policy with explicit data-tier destinations, resource controls, health probes, and secret hygiene.

## Residual Risks Blocking Production Claim

- GitHub Actions push run `33196601954` and pull-request run `33196610386` passed for exact release `93a54a8124f444d059538679ae492495da9d1e5c`; the uploaded HTTPS release artifact still needs to be recorded in the staging manifest.
- No staging `terraform plan/apply` has proven live AWS, EKS, RDS, Redis, ALB, DNS, ACM, IRSA, Secrets Store CSI, or rollback paths.
- Native-device/EAS validation is still required for mobile AES-GCM outside Node/WebCrypto shims.
- Deployed OTLP collector/backend, dashboard import, alert delivery, and retention evidence are still missing.
- Staging performance evidence for the 5,000 req/s and P99 under 200ms target is still missing.
- AI citation verification still proves citation presence against retrieved context, not claim-to-source semantic grounding; structured source spans and claim validation remain a product/security requirement.
- DRR-001 is closed: the locked Expo xcode tooling path now resolves `uuid@11.1.1` with a passing CommonJS compatibility smoke.
- DRR-002 is closed locally: Metro resolves the dependency-free repository-owned `mobile/vendor/image-size` compatibility package, which omits the affected HEIF/ICNS/JXL parsers; `mobile/metro.config.js` also blocks the affected parser and asset formats. The package and mobile audit/build gates must be re-run whenever Expo/Metro changes.
