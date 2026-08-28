# Phase 02: Auth, RBAC & Zero-Knowledge

Source: `SF-roadmap.md` Phase 02. This is the required localized task map for identity, tenant authorization, and client encryption.

Local implementation: tracked and gated.
External evidence: pending staging abuse, MFA, secret rotation, and native-device proof.

## Scope

- Versioned authentication, short-lived access tokens, opaque refresh rotation, MFA, and tenant context.
- Shared Argon2id server cryptography in `pkg/crypto_utils/` with compatibility aliases in `internal/domain/auth/`.
- Web/mobile journal encryption where plaintext and passphrases remain client-local.

## Task Matrix

| ID | Roadmap task | Status | Evidence |
| --- | --- | --- | --- |
| P02-01 | Generate this phase sub-roadmap before auth mutations. | complete | `tools/validate-roadmap-artifacts.mjs` |
| P02-02 | Validate server-generated-tenant registration, login, JWT claims, route aliases, refresh rotation, logout, and MFA. | local complete | Go auth/route tests; `SF-architecture.md` API matrix |
| P02-03 | Keep password hashing bounded, salted, strict, and owned by `pkg/crypto_utils`. | local complete | `pkg/crypto_utils/password_test.go`; race test |
| P02-04 | Keep journal ciphertext-only across API/database boundaries and derive keys locally. | local complete | `tools/verify-journal-crypto.mjs`; client smoke gates |
| P02-05 | Prove deployed rate limits, secret injection/rotation, MFA operation, RLS, and native memory cleanup. | external pending | `AUTH-001`, `SEC-SECRETS-001`, native EAS evidence |

## Acceptance Evidence

- Local: Go unit/race tests, RLS integration, journal crypto verification, web/mobile smoke and type/build gates.
- Merge: route and schema surfaces remain mirrored in `SF-architecture.md`, `SF-roadmap.md`, and the Obsidian readiness note.
- Release: access, refresh, MFA, abuse, and tenant outcomes must be recorded from staging with no plaintext journal evidence.

## External Blockers

- Staging identity provider behavior, account-scoped abuse observation, secret-manager rotation, and native Expo/EAS memory/crypto behavior require real environments and operator credentials.
