# Domain-Specific Security Audit

Status last updated: 2026-08-28

## Theological Study Platform Risks

ScriptureForgeAI handles tenant-scoped study data, encrypted personal journal entries, collaborative room events, AI-generated study material, citations, and Zoom meeting metadata. The highest domain-specific risks are:

- Cross-organization data disclosure between churches, cohorts, or study groups.
- Plaintext leakage from private journal reflections.
- Citation-free or hallucinated AI responses presented as trusted study material.
- Unauthorized access to live study rooms or replay/tampering of room state events.
- Meeting/webhook confusion where a Zoom event mutates the wrong room.

## Current Local Controls

- Tenant RLS tests cover same-tenant success and cross-tenant denial for handler paths and tenant tables.
- Journal handlers reject plaintext/passphrase fields and persist ciphertext plus crypto metadata only.
- AI generation routes fail verification when citations are absent or hallucinated and persist audit/citation rows without raw prompt content; audit rows retain a fixed redacted marker plus prompt length.
- Room WebSocket handling validates JWT claims, origin, room membership, event envelopes, frame size, deadlines, reconnect behavior, Redis-backed sequence ordering, and heartbeat-time membership/session revocation.
- Zoom integration validates webhook signatures, handles duplicate webhooks idempotently, maps meetings to internal rooms, and falls back when the Zoom client circuit is open.

## Non-Applicable Domains

- Healthcare/PHI-specific controls are not in scope unless future product direction introduces protected health information.
- Web3/smart-contract controls are not in scope because the repository does not contain blockchain integrations.

## Remaining Production Closure

- Staging tenant isolation proof against the deployed database role and connection pool.
- Native mobile crypto proof on real devices.
- Staging AI provider degradation and citation logging proof.
- Multi-instance WebSocket fan-out and Redis ordering proof.
- Live Zoom OAuth/webhook proof against real credentials.
