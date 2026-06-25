# Cryptography, Identity, and IAM Audit

Status last updated: 2026-06-25

## Authentication And Sessions

- Access tokens use signed JWTs and are verified at route boundaries.
- Access-token lifetime is constrained to the remediation target of approximately 15 minutes.
- Refresh tokens are opaque server-side session credentials that are hashed before persistence, rotated on refresh, scoped to user and organization, expirable, and revocable on logout.
- Privileged roles require TOTP MFA verification before login returns access and refresh tokens.
- Legacy `/api/auth/register` and `/api/auth/login` routes remain compatibility aliases for the canonical `/api/v1/auth/*` handlers and share the same abuse bucket.

Local evidence is in `tests/integration/auth_session_test.go` and `cmd/platform-engine/routes_test.go`.

## Authorization And Tenant Isolation

- Tenant-scoped handlers set `app.current_org_id` through `auth.SetTenantContext` inside transaction-scoped database work.
- PostgreSQL RLS is enabled on tenant tables and reinforced with tenant-aware constraints and composite tenant/user references.
- Registration forces unauthenticated signups to member-level roles.
- Handler/table integration tests cover same-tenant success and cross-tenant denial.

Local evidence is in `tests/integration/tenant_handler_rls_test.go` and `tests/integration/table_rls_test.go`.

## Journal Cryptography

- Journal plaintext and passphrases are client-side only.
- Backend journal handlers reject unknown plaintext/passphrase fields and persist encrypted payload metadata only.
- Web/mobile journal flows use AES-GCM with PBKDF2-derived, non-extractable key handles in the current harness.
- Mobile derivation wipes passphrase and salt byte buffers in a `finally` path after PBKDF2 setup.
- Mobile journal UI stores keys through disposable handles, clears replaced/unmounted key references, and rejects disposed-handle encryption.
- Mobile production readiness still requires EAS/native-device proof for the native crypto binding outside Node/WebCrypto shims.

Local evidence is in `tools/verify-journal-crypto.mjs` and the journal RLS integration tests.

## Infrastructure IAM And Secrets

- Terraform models workload secrets as AWS Secrets Manager ARNs through `app_secret_arns`.
- Workloads use an IRSA-annotated Kubernetes service account and a least-privilege Secrets Manager read policy scoped to the configured secret ARNs.
- Secrets Store CSI syncs `DATABASE_URL`, `JWT_SECRET_KEY`, `OPENAI_API_KEY`, and Zoom credential values into runtime Kubernetes secrets without committing plaintext values.
- Workload manifests consume `DATABASE_URL` from the synced secret and do not construct root database URLs from RDS master credentials.

Local evidence is in `build/terraform`, `security/secret_handling_review.md`, and `tools/validate-deployment-skeleton.mjs`.

## Remaining Production Closure

- Prove IRSA, Secrets Store CSI, and scoped database credentials in a real staging cluster.
- Capture clean pushed CI output for auth/RLS/session/security gates.
- Complete native-device mobile crypto validation.
- Perform cloud secret access review for GitHub Actions, AWS Secrets Manager, EKS workloads, and operator roles.
