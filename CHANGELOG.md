# Changelog

This file records repository-level implementation history. It is not a substitute for deployed staging evidence.

## Unreleased

### Production-readiness remediation

- Enforced typed Go JSON ingress contracts and typed room WebSocket error envelopes.
- Hardened authentication, refresh rotation, MFA lifecycle, tenant RLS boundaries, encrypted journal persistence, and client token recovery.
- Hardened room creation and synchronization with authenticated WSS, strict event envelopes, Redis sequencing/fan-out, polling fallback, and shutdown cleanup.
- Hardened AI and Zoom integrations with bounded transport behavior, fail-closed configuration, sanitized faults, audit persistence, citation verification, offline fallback, and retry-safe webhook mapping.
- Added Rust scripture-ingestion validation, Terraform validation gates, CI evidence binding, and Serena/Obsidian drift checks.

### Evidence boundary

- Local gates and exact-SHA hosted CI are the current implementation evidence.
- Deployment, staging provider credentials, live RLS/KMS/TLS, load, observability, rollback, backup/restore, and native-device proof remain environment-owned release blockers.
