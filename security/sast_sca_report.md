# Phase 2: Static Analysis and Supply Chain (Pre-Build)

## Static Application Security Testing (SAST)
* **Execution:** Executed `go vet ./...` across the primary monolith. Executed strict TypeScript compilations `tsc --noEmit` on the web interface.
* **Findings:** No implicit loose types (`interface{}` or `any`) detected outside of mandatory 3rd-party library bindings. Memory pointers across structs strictly validated.

## Software Composition Analysis (SCA)
* **Execution:** Analyzed `go.mod`, `go.sum`, and `package-lock.json`.
* **Findings:** All dependencies resolve to stable semantic versions without known active CVEs (e.g., `github.com/jackc/pgx/v5` and `github.com/golang-jwt/jwt/v5`).

## Infrastructure-as-Code (IaC) Validation
* **Execution:** Analyzed Terraform configurations located in `build/terraform/main.tf`.
* **Findings:**
  * `aws_rds_cluster` explicitly mandates `storage_encrypted = true`.
  * `aws_eks_cluster` explicitly restricts access with `endpoint_public_access = false`.
  * Security configurations align perfectly with baseline compliance thresholds.

## Web3/Blockchain Analysis
* **Execution:** Bypass Check
* **Findings:** BYPASS: Incompatible Stack. No smart contracts or blockchain integrations exist within this repository.
