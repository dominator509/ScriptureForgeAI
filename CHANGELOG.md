# Changelog

This file records repository-level implementation history. It is not a substitute for deployed staging evidence.

## Unreleased

### Production-readiness remediation

- Enforced typed Go JSON ingress contracts and typed room WebSocket error envelopes.
- Hardened authentication, refresh rotation, MFA lifecycle, tenant RLS boundaries, encrypted journal persistence, and client token recovery.
- Hardened room creation and synchronization with authenticated WSS, strict event envelopes, Redis sequencing/fan-out, polling fallback, and shutdown cleanup.
- Added replica-wide Redis leased semaphores for active room WebSocket caps across global, tenant, and user scopes, with renewal, crash expiry, and fail-closed outage handling.
- Wired production abuse limiting to an atomic Redis fixed-window backend shared across replicas, with bounded remote identity registration and fail-closed 503 behavior when Redis is unavailable; local nil-client fallback remains explicit for isolated tests.
- Added a dedicated unauthenticated Redis abuse budget for `/api/webhooks/zoom`, with route coverage and strict staging evidence requiring the `zoom_webhook` profile and its redacted request/window assignments.
- Added bounded, environment-driven Zoom HTTP timeout/retry budgets with Terraform workload projection and finite nil-client fallback behavior.
- Bound login refresh-token persistence to the existing tenant transaction and bound journal writes to the authenticated server-derived salt ID/version.
- Added typed fail-closed authentication dependency handling for unconfigured database pools across registration, login, refresh, logout, and privileged MFA routes.
- Added refresh-token MFA assurance binding, unknown-environment gRPC fail-closed behavior, and least-privilege API/Rust Terraform workload secret separation.
- Added API-only AES-GCM TOTP seed envelopes with fail-closed handling for missing, malformed, or legacy plaintext MFA material.
- Added non-local Redis password enforcement and API-only Terraform secret injection for Redis authentication.
- Hardened AI and Zoom integrations with bounded transport behavior, fail-closed configuration, sanitized faults, audit persistence, citation verification, offline fallback, and retry-safe webhook mapping.
- Added Rust scripture-ingestion validation, Terraform validation gates, CI evidence binding, and Serena/Obsidian drift checks.

### Evidence boundary

- Local gates and exact-SHA hosted CI are the current implementation evidence.
- Deployment, staging provider credentials, live RLS/KMS/TLS, load, observability, rollback, backup/restore, and native-device proof remain environment-owned release blockers.
