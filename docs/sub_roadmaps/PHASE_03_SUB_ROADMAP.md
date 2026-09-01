# Phase 03: Rust Scripture Engine

Source: `SF-roadmap.md` Phase 03. This is the required localized task map for protobuf, tonic, and vector retrieval work.

Local implementation: tracked and gated.
External evidence: pending deployed mTLS, provider-backed ingestion, and semantic retrieval proof.

## Scope

- Versioned `proto/scripture.proto` contract and Rust 2021 tonic service.
- Tenant-scoped scripture ingestion and vector retrieval using the runtime schema shape.
- Bounded startup, health, metrics, trace context, mTLS, shared-secret, and organization metadata boundaries.

## Task Matrix

| ID | Roadmap task | Status | Evidence |
| --- | --- | --- | --- |
| P03-01 | Generate this phase sub-roadmap before protobuf/service mutations. | complete | `tools/validate-roadmap-artifacts.mjs` |
| P03-02 | Maintain the protobuf contract and checked-in Rust build lane. | local complete | `tools/verify-rust-protobuf.mjs`; `cargo test --locked` |
| P03-03 | Validate bounded text, real 1536-dimensional embeddings, tenant RLS, and atomic upserts. | local complete | Rust tests; Docker RLS gate |
| P03-04 | Preserve Go-to-Rust health/readiness and sanitized failure behavior. | local complete | Go/Rust probe and readiness tests |
| P03-05 | Prove deployed mTLS, secret rotation, cross-namespace access, ingestion, and retrieval quality. | external pending | `RUST-GRPC-001` and staging artifacts |

## Acceptance Evidence

- Local: protobuf generation verification, Rust tests, Go tests, and readiness checks without external provider calls.
- Merge: protobuf and runtime route/schema references remain reflected in the architecture and readiness surfaces.
- Release: staging must prove authenticated gRPC traffic, tenant binding, certificate rotation, and semantic retrieval results.

## External Blockers

- A deployed Rust service, real TLS/CSI material, provider-generated embeddings, database data, and cross-service staging traffic are required for final evidence.
