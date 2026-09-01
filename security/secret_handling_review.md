# Secret Handling Review

Status last updated: 2026-06-25

## Scope

Reviewed tracked and untracked repo text surfaces for secret-handling readiness:

- Runtime configuration references in Go, Rust, web, mobile, and Terraform.
- Terraform example input files and backend examples.
- GitHub Actions workflow environment values.
- Test-only credentials used for deterministic unit/integration tests.
- Ignore rules for local env files, Terraform state, tool caches, and build outputs.

## Current Controls

- Application secrets are loaded from runtime environment variables, not hard-coded production values:
  - `DATABASE_URL`
  - `REDIS_URL`
  - `JWT_SECRET_KEY`
  - `JOURNAL_SALT_SECRET` (distinct from `JWT_SECRET_KEY` and at least 32 bytes in staging/production)
  - `OPENAI_API_KEY`
  - Zoom credential variables and webhook secret token
  - web/mobile public API base URLs
- Terraform references AWS Secrets Manager ARNs through `app_secret_arns` instead of storing plaintext secret values in Kubernetes workload specs.
- Terraform defines an IRSA-scoped workload service account, a least-privilege Secrets Manager read policy for those ARNs, and a Secrets Store CSI `SecretProviderClass` that syncs `DATABASE_URL`, `JWT_SECRET_KEY`, `JOURNAL_SALT_SECRET`, `OPENAI_API_KEY`, and Zoom credential environment variables into API/Rust pods from AWS Secrets Manager.
- `terraform.tfvars.example` contains placeholder account IDs, placeholder image digests, placeholder ACM/Secrets Manager ARNs, and no root database password input; Aurora manages that credential in Secrets Manager.
- `.gitignore` now excludes local `.env`, `.env.*`, Terraform state, local tool caches, and build outputs while allowing committed example env files.
- `tools/validate-secret-hygiene.mjs` scans repo text files for high-confidence secret patterns and validates required ignore/placeholder markers.
- CI is configured to run both the local secret hygiene validator and TruffleHog.

## Accepted Test Values

The repo intentionally contains deterministic test-only values such as `test-secret`, `secret`, placeholder JWT secrets, and disposable local Postgres URLs. These are not production credentials and are scoped to unit/integration tests or local disposable containers.

## Remaining Production Closure

This local review does not replace release-time secret scanning or cloud-side evidence. Before a production claim, capture:

- Clean pushed CI output from `tools/validate-secret-hygiene.mjs` and TruffleHog.
- Confirmation that real staging/production secrets live only in the chosen secret manager or CI secret store.
- Evidence that Terraform state is remote, encrypted, access-controlled, and does not contain plaintext application secrets.
- The Terraform skeleton uses Aurora-managed master credentials and a customer-managed KMS key instead of accepting a root password variable, reducing plaintext-equivalent credential exposure in state; live state backend and secret-rotation proof remain required.
- Staging proof that the Secrets Store CSI driver and AWS provider are installed, IRSA can read only the configured secret ARNs, synced Kubernetes secrets are created without plaintext or base64-encoded secret values in evidence artifacts, and `DATABASE_URL` uses a scoped application database user instead of the RDS root user.
- Staging proof that JWT and journal salt are separate high-entropy secret objects, both are synced to the API, rotation preserves the contract, and the journal salt never falls back to `JWT_SECRET_KEY`.
- Rotated staging credentials after any test deployment that used temporary values.
- Owner review of secret access roles for GitHub Actions, AWS Secrets Manager, EKS workloads, and operators.
