# Changelog

This file records repository-level implementation history. It is not a substitute for deployed staging evidence.

## Unreleased

### Production-readiness remediation

- Added irreversible AI audit prompt redaction: historical `ai_request_logs` bodies are scrubbed, and new rows retain only a fixed redaction marker plus prompt byte length while preserving status, errors, and citation trails.
- Added Terraform Kubernetes network-policy skeleton: application namespace ingress/egress defaults to deny, with explicit API, Rust, web, DNS, data-tier, Prometheus, OTLP, and HTTPS provider flows plus regression validation against unrestricted pod egress.
- Enforced typed Go JSON ingress contracts and typed room WebSocket error envelopes.
- Hardened authentication, refresh rotation, MFA lifecycle, tenant RLS boundaries, encrypted journal persistence, and client token recovery.
- Hardened room creation and synchronization with authenticated WSS, strict event envelopes, Redis sequencing/fan-out, polling fallback, and shutdown cleanup.
- Normalized web/mobile API and WebSocket base URLs at the client configuration boundary, rejecting credential-bearing, query-bearing, or fragment-bearing strict-environment endpoints before they can generate malformed requests or socket paths.
- Made AI provider environment values whitespace-safe: blank API keys fail closed before chat or embedding transport, while configured endpoint and model values are trimmed at construction.
- Added replica-wide Redis leased semaphores for active room WebSocket caps across global, tenant, and user scopes, with renewal, crash expiry, and fail-closed outage handling.
- Wired production abuse limiting to an atomic Redis fixed-window backend shared across replicas, with bounded remote identity registration and fail-closed 503 behavior when Redis is unavailable; local nil-client fallback remains explicit for isolated tests.
- Added a dedicated unauthenticated Redis abuse budget for `/api/webhooks/zoom`, with route coverage and strict staging evidence requiring the `zoom_webhook` profile and its redacted request/window assignments.
- Added bounded, environment-driven Zoom HTTP timeout/retry budgets with Terraform workload projection and finite nil-client fallback behavior.
- Wired the configured Zoom `MeetingAdapter` into production room creation, persisted tenant-scoped meeting mappings and safe join metadata, and kept host start URLs out of room responses.
- Bound login refresh-token persistence to the existing tenant transaction and bound journal writes to the authenticated server-derived salt ID/version.
- Added typed fail-closed authentication dependency handling for unconfigured database pools across registration, login, refresh, logout, and privileged MFA routes.
- Closed the privileged MFA enrollment bootstrap deadlock: unenrolled privileged login now returns a no-refresh, short-lived purpose-bound setup token; middleware restricts it to MFA setup routes, handlers re-check the current role and reject the setup token after activation, and web/mobile expose memory-only enrollment and activation helpers.
- Closed the public registration tenant-selection gap: registration now creates a server-generated workspace in the RLS-scoped transaction, forces the initial member role, and web/mobile callers send only a bounded workspace name.
- Closed the room token lifetime gap: validated JWTs now require `exp`, and active room WebSockets close when the access token expires instead of retaining an authenticated stream indefinitely.
- Bound privileged MFA verification attempts to the existing distributed tenant/user abuse limiter, preventing rotating client IPs from bypassing TOTP brute-force protection.
- Bounded the Rust metrics listener's first-request read with a clamped `RUST_ENGINE_METRICS_READ_TIMEOUT_MS` deadline to prevent idle-connection exhaustion.
- Protected the Go API `/metrics` endpoint in non-local environments with constant-time bearer-token authentication, fail-closed missing-secret behavior, API-only Terraform secret injection, validator coverage, and authenticated staging probe support.
- Added the irreversible `000005_mfa_legacy_plaintext_cleanup` migration to clear legacy plaintext TOTP seeds and force safe re-enrollment; CI and Docker-backed RLS setup now apply the complete ordered up-migration set, including `000003`.
- Corrected local Compose to use the current root-context containers, pgvector migrations, and URL-based runtime configuration.
- Removed the unreachable nested in-memory API/WAL runtime, replaced mock disaster-recovery scripts with checksummed PostgreSQL archive helpers requiring explicit isolated restores, and marked the old emulation report as historical; CI/local tooling now validates the boundary.
- Recorded the current exact-SHA verification boundary: hosted push/PR runs for `0c63a86a32795f5692fd85d2bf1280ac8f8b2c43` failed before workflow steps, while the clean local matrix executed 35/35 gates with 34 passing and only the Docker-backed RLS gate blocked by the unavailable Docker backend.
- Corrected the hosted tenant-isolation integration assertion to match the submitted room title, allowing the real PostgreSQL/RLS suite to verify room-to-Zoom configuration without a stale test expectation.
- Verified the corrected branch tip `24f6d7d9885ec357a569fc30216832c4d20bf9d5` in hosted push run `33159284084` and pull-request run `33159292139`; both completed successfully with PostgreSQL/RLS integration and CI release evidence upload.
- Refreshed exact-SHA local evidence for `7e52902ba92032e05bebf27b5293b6cb61c5a7ca`: 35/35 gates ran with 34 passing, clean/synchronized Git metadata, and only the fail-closed Docker-backed RLS gate blocked by the unreachable local Docker server endpoint.
- Marked the superseded `audit_report.txt` as historical so stale completion claims cannot be mistaken for current readiness evidence.
- Hardened the disposable Docker/RLS gate with daemon readiness probing and bounded Docker subprocess timeouts; unavailable Docker now reports a deterministic environment blocker instead of hanging local validation.
- Repaired the RLS production-wiring regression fixture so its negative membership-override test remains stable across Go struct formatting changes.
- Added refresh-token MFA assurance binding, unknown-environment gRPC fail-closed behavior, and least-privilege API/Rust Terraform workload secret separation.
- Added API-only AES-GCM TOTP seed envelopes with fail-closed handling for missing, malformed, or legacy plaintext MFA material.
- Added non-local Redis password enforcement and API-only Terraform secret injection for Redis authentication.
- Hardened AI and Zoom integrations with bounded transport behavior, fail-closed configuration, sanitized faults, audit persistence, citation verification, offline fallback, and retry-safe webhook mapping.
- Added Rust scripture-ingestion validation, Terraform validation gates, CI evidence binding, and Serena/Obsidian drift checks.
- Added strict staging/production PostgreSQL TLS URL validation to the Go API and Rust scripture engine, with local-development compatibility and deployment-validator coverage.
- Verified the current metrics-auth remediation head `e07f423b519566277bf5f9d72681309c79d8cb00` in hosted Security Pipeline Verification run `33184095128`; all workflow steps passed, including the synchronized Obsidian snapshot and CI release-evidence upload.
- Enforced the existing session-revocation cutoff across protected HTTP routes and refresh issuance, denied expired-token logout side effects, and added regression coverage for pre-logout access tokens and independent refresh families.
- Scoped user email uniqueness to `(organization_id, email)` through migration `000008_tenant_scoped_user_email`, made registration conflicts generic, and added dummy Argon2id verification for missing-user login attempts.
- Added the bounded environment-driven `AI_MAX_OUTPUT_TOKENS` provider request budget and Terraform projection.
- Scoped API/Rust database-port NetworkPolicy egress to declared `data_tier_cidrs` with validator regression coverage.
- Made failed room-provisioning cleanup use a bounded context detached from client cancellation and emit sanitized dependency telemetry.
- Added verified Zoom webhook lifecycle persistence: `meeting.started` and `meeting.ended` update the mapped durable `live_rooms.is_active` row under a dedicated exact-meeting RLS update policy before Redis publication, with tenant integration coverage.
- Added bounded missed-webhook reconciliation to `GET /api/v1/rooms/active`: terminal external meeting statuses deactivate exact tenant-scoped durable and Redis room state, while provider errors preserve state for retry and offline fallback rooms are skipped.
- Hardened the Redis room-state adapter to return typed `503`-class room-state faults for nil receivers or unconfigured clients across event, active-state, participant-duration, polling, and webhook-idempotency operations instead of panicking.
- Added mobile session continuity through exact Expo SecureStore dependency pinning, serialized secure persistence, startup refresh/cleanup, and memory-only MFA enrollment state; mobile smoke coverage proves the record boundary and bootstrap behavior.
- Bound AI citations to RAG segment labels: verification now accepts only exact source labels at segment starts, and retrieved line breaks are normalized so citation-like source text cannot become metadata.
- Hardened MapReduce chunk splitting so a limit smaller than the first UTF-8 rune emits that rune intact instead of returning invalid text; regression coverage preserves bounded processing behavior.
- Refreshed the durable audit, roadmap, threat-model, and Obsidian records with the passing exact-SHA hosted CI evidence and the remaining staging-only release blockers.

### Evidence boundary

- Local gates and exact-SHA hosted CI are the current implementation evidence.
- Deployment, staging provider credentials, live RLS/KMS/TLS, load, observability, rollback, backup/restore, and native-device proof remain environment-owned release blockers.
