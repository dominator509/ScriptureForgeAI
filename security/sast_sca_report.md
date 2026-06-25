# Static Analysis And Supply Chain Report

Status last updated: 2026-06-25

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
- The remaining mobile moderate Expo tooling advisory is tracked as accepted risk in `security/dependency_risk_register.md` as DRR-001.
- Rust cargo tests pass with a vendored `protoc` build path, but `sqlx-postgres v0.7.4` emits a future-incompatibility warning that should be addressed in a deliberate Rust dependency-lane upgrade.

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
