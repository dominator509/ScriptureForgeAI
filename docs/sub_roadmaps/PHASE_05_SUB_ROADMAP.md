# Phase 05: Live Sockets & Zoom Sync

Source: `SF-roadmap.md` Phase 05. This is the required localized task map for room synchronization and meeting adapters.

Local implementation: tracked and gated.
External evidence: pending multi-replica load, deployed Redis telemetry, and real Zoom lifecycle proof.

## Scope

- Authenticated, origin-checked room WebSocket streams with polling fallback.
- Atomic Redis Lua sequencing/latest-state/publication and bounded replica fan-out.
- Tenant-scoped room persistence, membership checks, Zoom mapping, retries, circuit breaker, and idempotent webhooks.

## Task Matrix

| ID | Roadmap task | Status | Evidence |
| --- | --- | --- | --- |
| P05-01 | Generate this phase sub-roadmap before socket/meeting mutations. | complete | `tools/validate-roadmap-artifacts.mjs` |
| P05-02 | Validate room creation, active/state routes, strict event envelopes, and membership. | local complete | Go room HTTP/WS tests; RLS gate |
| P05-03 | Sequence accepted mutations through Redis and broadcast only valid events. | local complete | miniredis replica fan-out tests |
| P05-04 | Preserve Zoom timeout, fallback, signature, mapping, retry, circuit, and duplicate safety. | local complete | Zoom adapter/webhook tests |
| P05-05 | Prove deployed WSS origin/member behavior, reconnect/polling continuity, replica ordering, and Zoom mapping. | external pending | `ROOM-WS-001`, `EXT-ZOOM-001` |

## Acceptance Evidence

- Local: room tests cover invalid origins/membership/events, Redis ordering/fan-out, shutdown, polling, and Zoom fakes.
- Merge: canonical room routes and event envelope remain mirrored in the architecture and readiness surfaces.
- Release: staging artifacts must prove authenticated WSS, contiguous sequence numbers, polling latest-state parity, and distinct replica telemetry.

## External Blockers

- Multi-replica Redis, ingress/TLS, real Zoom credentials/webhooks, and concurrent load testing require staging infrastructure and operator control.
