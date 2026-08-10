# Static Analysis And Supply Chain Report

Status last updated: 2026-08-10

## Static Application Security Testing

Current CI is configured to run:

- `go test ./...`
- DB-backed Go integration tests against `pgvector/pgvector:pg16`
- `go vet ./...`
- web smoke/typecheck/build gates
- mobile smoke/build-compatible gates
- Rust `cargo test`
- Terraform fmt/init/validate
- observability, secret hygiene, and deployment skeleton validators
- TruffleHog secret scanning

The current local remediation evidence is tracked in `FUNCTIONALITY_AUDIT_BRIEFING.md`. A production claim still requires the full matrix to pass in a clean pushed GitHub Actions run from the exact release branch.

## Software Composition Analysis

- Web enforces `npm audit --audit-level=moderate`.
- Mobile enforces `npm audit --audit-level=high`.
- Web dependency hardening updated the PostCSS override to `8.5.26`, which resolves the prior `nanoid <3.3.17` high finding.
- Mobile leaf dependency hardening resolves `brace-expansion`, `js-yaml`, `nanoid`, `postcss`, and `uuid`; DRR-001 is closed in `security/dependency_risk_register.md`.
- The mobile `npm audit --audit-level=high` gate is green after Metro is pinned to the dependency-free repository-owned `mobile/vendor/image-size` compatibility package. The package supports only Metro's safe asset formats, rejects the affected HEIF/ICNS/JXL parser path, and is covered by parser, dependency-risk, Metro-loading, and mobile build checks. DRR-002 is closed locally and must be re-evaluated on every Expo/Metro refresh.
- Rust cargo tests pass with a vendored `protoc` build path. The prior `sqlx-postgres v0.7.4` future-incompatibility warning is remediated by the `pgvector 0.4.2` / `sqlx-postgres 0.9.0` lane, and `tools/verify-rust-protobuf.mjs` guards against regressing to the old lane.

## Infrastructure-As-Code Validation

Terraform now lives in split files under `build/terraform` rather than the deleted `build/terraform/main.tf` placeholder. Current local checks cover:

- Remote S3 backend shape and example backend configuration.
- Variable-driven AWS account, subnet, image, certificate, secret ARN, OTLP, and workload resource inputs.
- EKS, RDS, Redis, ECR, Kubernetes deployment/service/ingress boundaries.
- TLS ALB ingress annotations and `/ready` health checks.
- IRSA and Secrets Store CSI workload secret wiring.
- API/Rust/web resource requests and limits, zone topology spread constraints, and PodDisruptionBudgets.
- API/Rust/web Horizontal Pod Autoscalers with CPU and memory utilization targets.
- Aurora PostgreSQL backup retention, backup/maintenance windows, CloudWatch PostgreSQL log export, tag copying to snapshots, deletion protection, and named final snapshot.
- API/Rust/web rolling update strategy with rollout history retention and zero unavailable pods during deploys.
- Terraform fmt/validate and deployment skeleton invariant validation.

Live production readiness still requires staging `plan/apply`, TLS/DNS/ACM proof, remote-state access proof, and real cluster/runtime validation.
