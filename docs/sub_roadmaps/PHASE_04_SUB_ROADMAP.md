# Phase 04: AI Orchestrator Pipeline

Source: `SF-roadmap.md` Phase 04. This is the required localized task map for citation-first RAG generation.

Local implementation: tracked and gated.
External evidence: pending real provider, degradation, audit telemetry, and production quality proof.

## Scope

- Input validation, bounded MapReduce context assembly, vector retrieval, and LLM adapter policy.
- Citation verification that rejects unmatched or citation-free output.
- Fail-closed audit persistence for `ai_request_logs` and `citation_trails`.

## Task Matrix

| ID | Roadmap task | Status | Evidence |
| --- | --- | --- | --- |
| P04-01 | Generate this phase sub-roadmap before AI pipeline mutations. | complete | `tools/validate-roadmap-artifacts.mjs` |
| P04-02 | Validate prompt, RAG, LLM, and MapReduce dependency readiness. | local complete | AI domain/handler tests |
| P04-03 | Bound provider requests, response bodies, retries, cancellation, and aggregate output. | local complete | LLM/embedding/MapReduce tests |
| P04-04 | Reject hallucinated or missing citations and persist verified audit trails. | local complete | AI verification and audit tests; RLS gate |
| P04-05 | Prove real provider behavior, timeout degradation, audit telemetry, and citation quality. | external pending | `EXT-AI-001` staging evidence |

## Acceptance Evidence

- Local: provider calls use explicit fakes, no external network is required, and all failure paths return typed sanitized faults.
- Merge: the canonical AI route and audit schema remain mirrored across route, architecture, roadmap, and readiness documents.
- Release: each generation, citation, and audit artifact must share the exact release, request, citation, user, and organization identity.

## External Blockers

- Real provider credentials, deployed vector/Rust dependencies, OTEL/audit backend, and representative theological quality review remain environment-owned.
