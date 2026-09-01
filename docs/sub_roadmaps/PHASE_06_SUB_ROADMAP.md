# Phase 06: Web & Mobile UX Assembly

Source: `SF-roadmap.md` Phase 06. This is the required localized task map for the functional web and mobile clients.

Local implementation: tracked and gated.
External evidence: pending deployed browser smoke, native device crypto, and release telemetry.

## Scope

- Environment-driven API and WebSocket clients with auth bootstrap, refresh, logout, rooms, and journal flows.
- Next.js web build/type safety and Expo/React Native build/smoke checks.
- Client-only journal key derivation and memory cleanup boundaries.

## Task Matrix

| ID | Roadmap task | Status | Evidence |
| --- | --- | --- | --- |
| P06-01 | Generate this phase sub-roadmap before client mutations. | complete | `tools/validate-roadmap-artifacts.mjs` |
| P06-02 | Keep web and mobile API/WS base URLs environment-driven. | local complete | client config and smoke tests |
| P06-03 | Validate login, refresh, MFA challenge, journal save/load, and logout lifecycle. | local complete | web/mobile smoke suites |
| P06-04 | Validate room list/create/select, reconnect, polling, and authenticated stream setup. | local complete | client room tests and type checks |
| P06-05 | Prove deployed browser behavior, native EAS crypto cleanup, and multi-device synchronization. | external pending | `WEB-SMOKE-001`, native device evidence |

## Acceptance Evidence

- Local: web smoke/typecheck/build, mobile smoke/build-check, journal crypto verification, and mocked API/WS contracts.
- Merge: client routes/config and encryption notes remain reflected in `REPO_BRIEF.md`, `SF-roadmap.md`, and readiness tracking.
- Release: deployed browser and native-device artifacts must bind to the release SHA and avoid local/mock-only claims.

## External Blockers

- A deployed web environment, real browser session, Expo/EAS device matrix, and production telemetry are required for final UX evidence.
