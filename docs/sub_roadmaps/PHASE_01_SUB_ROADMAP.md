# Phase 01: Infrastructure & Data Core

Source: `SF-roadmap.md` Phase 01. This is the required localized task map for the infrastructure and data-core phase.

Local implementation: tracked and gated.
External evidence: pending staging deployment, backup/restore, and operator-owned AWS proof.

## Scope

- Terraform EKS/RDS/Redis/network skeleton and validated runtime configuration.
- Linear PostgreSQL migrations, tenant RLS, vector indexes, and bounded API pool startup.
- Local integration evidence without committing state, credentials, or environment manifests.

## Task Matrix

| ID | Roadmap task | Status | Evidence |
| --- | --- | --- | --- |
| P01-01 | Generate this phase sub-roadmap before infrastructure mutations. | complete | `tools/validate-roadmap-artifacts.mjs` |
| P01-02 | Define encrypted Terraform deployment boundaries and runtime inputs. | local complete | `tools/validate-deployment-skeleton.mjs`; `build/terraform/` |
| P01-03 | Apply extensions, core schema, tenant policies, and vector indexes through migrations. | local complete | `tools/validate-rls-schema.mjs`; Docker RLS gate |
| P01-04 | Use bounded PostgreSQL/Redis startup probes and explicit pool lifecycle settings. | local complete | Go unit tests; CI service gate |
| P01-05 | Prove deployed encryption, remote state, RLS, backup, restore, and rollback behavior. | external pending | `DEPLOY-TF-001`, `DATA-RLS-001`, `BACKUP-001` |

## Acceptance Evidence

- Local: Terraform fmt/validate, schema drift validation, Docker-backed RLS integration, Go tests, and Go vet.
- Merge: pinned security workflow runs the same artifact validator and infrastructure gates.
- Release: staging evidence must bind every deployment and data result to the exact release SHA.

## External Blockers

- AWS account inputs, remote Terraform state, KMS/TLS/DNS, EKS/RDS/Redis deployment, scoped database credentials, and backup/restore artifacts are operator-owned.
- Local validation does not prove deployed performance, encryption, failover, or rollback behavior.
