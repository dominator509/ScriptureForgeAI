# ScriptureForgeAI

## Local Remediation Prerequisites

The audit remediation work targets the repo-current toolchain:

- Go toolchain `1.24.3`
- Node.js with `npm ci` run inside `web/`
- Rust stable for `services/scripture-engine`; protobuf generation uses vendored `protoc` via Cargo build dependencies, and the verifier checks the checked-in lockfile for vendored platform packages. The cargo gate deliberately poisons ambient `PROTOC`, so a separate `protoc` binary is optional for local builds.
- Terraform `1.6+`

Useful validation commands:

```bash
rtk node tools/verify-project-path.mjs
rtk go test ./...
rtk npm run typecheck
rtk npm run build
rtk cargo test --locked
rtk terraform -chdir=build/terraform init -backend=false
rtk terraform -chdir=build/terraform fmt -check -recursive
rtk terraform -chdir=build/terraform validate
rtk node tools/validate-observability.mjs
rtk node tools/validate-rls-schema.mjs
rtk node tools/validate-secret-hygiene.mjs
rtk node tools/validate-deployment-skeleton.mjs
rtk node tools/validate-staging-evidence.mjs
rtk node tools/validate-ci-evidence-gates.mjs
rtk node tools/validate-security-artifacts.mjs
rtk node tools/verify-journal-crypto.mjs
```

Before collecting staging or release evidence from a local shell, run the stricter PATH check:

```bash
rtk node tools/verify-project-path.mjs --strict-staging
```

The default PATH check covers local build/test gates. `--strict-staging` also requires the deployment/evidence tools used for production proof collection (`gopls`, `psql`, `kubectl`, `aws`, and `gh`) while still treating standalone `protoc` as optional because the Rust engine vendors it through Cargo.
On Windows, `tools\use-project-path.cmd --strict-staging` and `powershell -ExecutionPolicy Bypass -File tools\use-project-path.ps1 -StrictStaging` activate the repo-local Go/Rust/Terraform toolchain, add common user/system install paths for Go tools, AWS CLI, and PostgreSQL clients when present, then run the same strict check. Both helpers can also prefix a command, for example `tools\use-project-path.cmd cargo test --manifest-path services\scripture-engine\Cargo.toml --locked` or `powershell -ExecutionPolicy Bypass -File tools\use-project-path.ps1 -Quiet node tools\verify-project-path.mjs --strict-staging`, so local tools resolve even when a fresh shell has not inherited PATH changes. Current local evidence resolves `gopls`, `psql`, `docker`, `kubectl`, `aws`, and `gh`; standalone `protoc` remains optional because the Rust engine vendors it through Cargo.

OpenTelemetry tracing is optional for local runs and enabled when an OTLP/HTTP collector endpoint is configured:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.observability:4318
OTEL_EXPORTER_OTLP_INSECURE=true
OTEL_SERVICE_NAME=scriptureforge-api
SERVICE_VERSION=2026.06.25
DEPLOYMENT_ENVIRONMENT=staging
```

The Terraform skeleton maps the same production values through `service_version`, `otel_exporter_otlp_endpoint`, and `otel_exporter_otlp_insecure` so the API deployment can emit traces once a collector is available.

The Rust scripture engine emits JSON startup/request/error logs, extracts W3C `traceparent` metadata from gRPC requests into `trace_id` log fields, exposes Prometheus text metrics on `RUST_ENGINE_METRICS_ADDRESS` defaulting to `0.0.0.0:9102`, and receives `OTEL_SERVICE_NAME`, `SERVICE_VERSION`, `DEPLOYMENT_ENVIRONMENT`, and `OTEL_EXPORTER_OTLP_ENDPOINT` through Terraform. In staging/production, the Rust gRPC listener requires server TLS plus client certificates and a `GRPC_ENGINE_SHARED_SECRET`; the Go client sends the verified organization ID as `x-scriptureforge-organization-id`. This is baseline Rust gRPC observability and log/metric correlation, not proof that a deployed OTLP collector is receiving Rust spans.

Runtime secrets are modeled through AWS Secrets Manager ARNs in `app_secret_arns`. The skeleton uses IRSA plus the Secrets Store CSI driver to sync `DATABASE_URL`, `JWT_SECRET_KEY`, `OPENAI_API_KEY`, Zoom credential variables, `GRPC_ENGINE_SHARED_SECRET`, and the JSON `GRPC_ENGINE_TLS_*` certificate material into API/Rust pods without committing plaintext secret values. The `database_url` secret should point at an application database user, not the RDS root user. A staging cluster must already have the Secrets Store CSI driver and AWS provider installed before apply.

Zoom API calls use a bounded HTTP client, retry transient `429`/`5xx` responses, open a circuit after repeated failures, and fall back to `offline://in-person` meeting metadata when Zoom is unavailable. `ZOOM_MAX_RETRIES` controls retry attempts and defaults to `2`; staging still must capture real OAuth, webhook signature, endpoint URL validation, timeout/circuit, fallback, duplicate delivery, and room-mapping artifacts before `EXT-ZOOM-001` can pass.

`tools/validate-rls-schema.mjs` verifies the migration still forces RLS on every tenant-scoped table, keeps `app.current_org_id` USING/WITH CHECK policies, retains matching table-level same-tenant read, cross-tenant read-denial, cross-tenant write-denial, plus handler-level RLS proof markers, and rejects production room/socket route wiring that bypasses DB-backed membership checks. It is a local schema drift guard, not deployed database proof.

`tools/validate-deployment-skeleton.mjs` verifies the local Terraform skeleton keeps the expected remote state, TLS ingress, IRSA/Secrets Store CSI, runtime secret references, health/readiness probes, Rust gRPC probe, API-to-Rust gRPC address injection, production-like Go runtime config fail-closed behavior, OTLP env wiring, resource request/limit controls, pod disruption budgets, topology spread constraints, horizontal pod autoscalers, and web/API image/config boundaries. It is a drift guard for the skeleton and runtime config shape, not live AWS deployment proof.

The Aurora PostgreSQL skeleton enables encrypted storage, deletion protection, PostgreSQL log export, tag copying to snapshots, automated backup retention, explicit backup/maintenance windows, and a named final snapshot. API, Rust, and web deployments retain rollout history and use explicit rolling updates with zero unavailable pods. Production readiness still requires a staging backup/restore drill and rollback exercise.

`production-readiness/staging-evidence.example.json` is the required evidence contract for the remaining production claim. `tools/validate-staging-evidence.mjs` validates that the manifest covers source-control/CI, Terraform plan/apply, TLS, Kubernetes workloads, IRSA/CSI secrets, scoped database credentials, RLS, Redis/WebSocket sequencing, Rust gRPC, observability, web/mobile client smokes, Zoom, AI provider behavior, load tests, rollback, backup/restore, and owner/security signoff. The checked-in example intentionally stays `pending_external`; a real release should bootstrap an environment-specific evidence file for the current release candidate, fill passed/blocked/accepted-risk entries with artifact paths or URLs, and run `STAGING_EVIDENCE_FILE=<path> node tools/validate-staging-evidence.mjs`.

```bash
rtk node tools/bootstrap-staging-evidence.mjs \
  --out production-readiness/staging-evidence.staging.json \
  --environment staging
```

Environment-specific evidence manifests are git-ignored because they may contain staging artifact URLs and operational notes. The bootstrap command uses the current `git rev-parse HEAD` as `release_candidate` unless `--release-candidate` is supplied.

To print the exact remaining strict-release blockers from an environment manifest:

```bash
rtk node tools/report-staging-evidence-gaps.mjs \
  --manifest production-readiness/staging-evidence.staging.json
```

The reporter compares the manifest `release_candidate` to the current `git rev-parse HEAD` by default and prints a SHA mismatch as its own blocker. It also runs strict staging PATH readiness and reports `STAGING-PATH-TOOLS` when required evidence-collection tools such as `psql` or `aws` are missing. Use `--expected-release-candidate <sha>` when checking a manifest for a different release checkout, and use `--format json` when a release handoff needs machine-readable counts and evidence requirements. The command exits non-zero until every strict-release item is passed, strict staging PATH readiness passes, and `SEC-SIGNOFF-001` is either passed or recorded as the only allowed `accepted_risk`.

Before claiming production readiness, run the same validator in strict release mode:

```bash
STAGING_EVIDENCE_FILE=production-readiness/staging-evidence.staging.json \
  rtk node tools/validate-staging-evidence.mjs --strict-release
```

Strict mode rejects placeholder or non-SHA release candidates, future-dated manifests, local/dev environment manifests, non-HTTPS/local/private artifact URLs, artifact evidence marked as mock, placeholder, synthetic, stubbed, test-only, dry-run, or local-only, plus any `pending_external`, `blocked`, or `failed` item. It also enforces probe-family markers for strict evidence summaries, such as abuse account-scoped login, WebSocket upgrade, verified redacted limiter-config markers, load-test thresholds, release linkage, artifact verification, and Redis/WebSocket sequence proof. It rejects `accepted_risk` outside `SEC-SIGNOFF-001`, so operational proof items such as deployment, TLS, RLS, observability, load, and rollback must be `passed`.

After strict evidence validation passes, run the final claim verifier from the release checkout:

```bash
STAGING_EVIDENCE_FILE=production-readiness/staging-evidence.staging.json \
LOCAL_GATE_REPORT_FILE=artifacts/local-gate-report.json \
  rtk node tools/verify-production-readiness.mjs
```

The verifier reruns strict manifest validation, requires the manifest `environment` to be `staging`, `production`, or `prod`, validates the full non-dry-run local gate report, requires strict staging PATH readiness, requires the Obsidian readiness snapshot to be in sync with the same manifest, release candidate, and strict PATH result, requires a clean git worktree, requires the branch to be neither ahead nor behind upstream, requires `release_candidate` to equal the current `git rev-parse HEAD` SHA, requires the local gate report `git_head` to match that same SHA, and rejects local gate reports observed before the staging evidence manifest was generated. When it fails, it prints the matching `tools/report-staging-evidence-gaps.mjs` command to show the complete blocker list.

The CI workflow is also guarded against gate drift:

```bash
rtk node tools/validate-ci-workflow.mjs
rtk node tools/validate-ci-evidence-gates.mjs
```

Those validators require the security workflow and CI release-evidence artifact to retain the Go, Postgres/RLS, load harness, evidence tooling, observability, RLS schema drift, Obsidian readiness snapshot, secret hygiene, deployment skeleton, web, mobile, Rust, Terraform, TruffleHog, and CI release-evidence gates. The workflow validator also checks release-evidence ordering so TruffleHog and tracked-file cleanliness run before the artifact is written, the artifact is validated before upload, and a reordered workflow cannot satisfy release evidence by string presence alone.

For repeatable local gate evidence, run the local gate runner:

```bash
rtk node tools/run-local-gates.mjs --report artifacts/local-gate-report.json
```

The runner executes the repo-local Go, Docker-backed RLS integration, web audit/smoke/typecheck/build, mobile high-severity audit/smoke/build-compatible, Rust, Terraform, observability, deployment skeleton, staging evidence, CI workflow, security artifact, secret hygiene, journal crypto, Obsidian readiness snapshot, and tooling test gates and writes a JSON report stamped with the current `git_head`, branch, upstream, ahead/behind counts, and `git status --short` cleanliness. The `tooling-tests` gate includes `tools/sync-obsidian-readiness.test.mjs` so strict PATH and release-candidate snapshot behavior stay covered by both local and CI gates. The `rls-db-integration` gate runs `node tools/run-rls-db-integration-docker.mjs` with `REQUIRE_DATABASE_URL=true`, starts the same `pgvector/pgvector:pg16` database shape used by CI, applies migrations inside the container, runs the RLS integration gate, and removes the disposable container unless `--keep` is passed. `node tools/run-rls-db-integration.mjs` remains available for CI or manually supplied migrated Postgres/pgvector databases where `DATABASE_URL` is already set. Use `--only go-test,go-vet` for a focused subset, `--dry-run` to print a pass-shaped plan without executing commands, and `--continue-on-failure` when you want one report containing every failure instead of stopping at the first failed gate.
Development evidence: `node tools\run-local-gates.mjs --continue-on-failure --report artifacts\local-gate-report-current.json` ran the current 30-gate matrix on 2026-06-28T05:03:26Z with 0 failures in the dirty but upstream-synced `codex/production-readiness-remediation` worktree. Treat that as a development snapshot only; release evidence still needs a clean worktree, exact release SHA, clean pushed CI, and staging artifacts.

Validate a full non-dry-run report before treating it as local readiness evidence:

```bash
rtk node tools/validate-local-gate-report.mjs --report artifacts/local-gate-report.json
```

Focused, dirty, unsynced, or dry-run reports can be checked during development with `--allow-subset`, `--allow-dirty`, `--allow-unsynced`, or `--allow-dry-run`, but those relaxed modes do not satisfy the full local gate evidence requirement. Local gate reports are also rejected if `observed_at` is future-dated relative to the validation date or if any required gate is marked skipped.

For source-control and CI release evidence, publish the exact release branch/SHA, let GitHub Actions upload the `ci-release-evidence` artifact, then validate either the downloaded artifact file or a raw artifact URL:

The security workflow runs on pushes to `main`, `develop`, and `codex/**`, plus pull requests into `main`, so remediation branches can produce CI evidence before a PR exists.

```powershell
rtk go run ./tools/ciprobe `
  -run-artifact-file artifacts/ci-release-evidence.txt `
  -commit-sha 0123456789abcdef0123456789abcdef01234567
```

```powershell
rtk go run ./tools/ciprobe `
  -run-artifact-url https://example.com/artifacts/github-actions-run.txt `
  -commit-sha 0123456789abcdef0123456789abcdef01234567
```

The report emits `SRC-CI-001` in `evidence_items` only when the artifact proves the exact release commit completed the required CI gates successfully and does not include failed/cancelled/stale/dirty-run markers. Remote artifact URLs must be HTTPS and non-local; a local file is accepted only for a downloaded GitHub Actions artifact from the release run. The CI artifact must list the gate IDs from `tools/run-local-gates.mjs`, the TruffleHog secret scan marker, GitHub ref/event metadata, and the clean-source-control marker written after the workflow verifies no tracked file drift; broad summaries such as "Go, web, and Terraform passed" are not enough for release evidence.

The workflow writes this artifact with `tools/write-ci-release-evidence.mjs` after the required local gates, TruffleHog step, and a tracked-file cleanliness check complete, immediately validates the local file with `tools/ciprobe`, and then uploads it as the `ci-release-evidence` artifact. `tools/validate-ci-workflow.mjs` enforces that order. The artifact names the full commit SHA, workflow, job, repository, ref, event, run URL, source-control cleanliness marker, successful conclusion, and required gate markers so it can be recorded into the staging evidence manifest with `tools/record-staging-evidence.mjs`.

`tools/stagingprobe` emits a JSON probe report for deployed HTTPS readiness checks that can be attached to the staging evidence manifest for `DEPLOY-TLS-001` and `CLIENT-WEB-001`:

```bash
rtk go run ./tools/stagingprobe \
  -api-base=https://api.staging.example \
  -web-base=https://app.staging.example \
  -dns-artifact-url=https://artifacts.staging.example/tls/dns.txt \
  -acm-artifact-url=https://artifacts.staging.example/tls/acm-certificate.txt \
  -web-auth-smoke-url=https://artifacts.staging.example/web/auth-smoke.txt \
  -web-journal-smoke-url=https://artifacts.staging.example/web/journal-smoke.txt \
  -web-room-smoke-url=https://artifacts.staging.example/web/room-smoke.txt \
  -timeout=5s
```

The probe requires HTTPS non-local API/web targets, checks API `/live` and `/ready`, checks the web root, records TLS version/certificate expiry, verifies HTTP-to-HTTPS redirects, and carries same-run HTTPS non-local artifacts proving DNS records plus ACM certificate status/TLS policy. Successful API/web/TLS/redirect probe summaries include verified marker lists so the recorder can reject markerless reachability claims. When `-web-base` is supplied, it also fetches HTTPS non-local browser-smoke artifacts and requires marker proof for login/register (`staging artifact`, `login`, `register`, `authenticated`, `https://`), encrypted journal save/load (`journal`, `encrypted`, `save`, `load`, `plaintext absent`), and room create/select/WebSocket connection (`room`, `create`, `select`, `WebSocket`, `connected`) before emitting `CLIENT-WEB-001`. It is an evidence collector for deployed service reachability, not a substitute for Terraform apply, Kubernetes rollout/resource artifacts, load, observability, or external-service proof. `DEPLOY-K8S-001` must come from `tools/deploymentprobe -probe-kubernetes`, which proves rollout status plus deploy/service/ingress/HPA/PDB resources.
The web runtime config rejects local or insecure API/WebSocket endpoints when `NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging|production|prod`; deployed browser smoke evidence should prove `NEXT_PUBLIC_API_BASE_URL=https://...` and `NEXT_PUBLIC_WS_BASE_URL=wss://...` rather than relying on localhost defaults.
The recorder rejects `DEPLOY-TLS-001` reports unless the claimed API/web targets include the expected live/readiness, TLS handshake, HTTP-to-HTTPS redirect probes, and verified marker summaries. It rejects `CLIENT-WEB-001` unless web root, web TLS, web redirect, all three fetched browser-smoke artifact probes, and matching marker summaries are present.
The strict release manifest validator also requires those TLS/readiness and browser-smoke marker summaries, so generic `stagingprobe` reports cannot satisfy `DEPLOY-TLS-001` or `CLIENT-WEB-001`.

Optional external-service smoke probes can exercise staging AI and Zoom routes, but they do not emit `EXT-ZOOM-001` or `EXT-AI-001`; those production evidence items must come from the dedicated artifact probes below:

```bash
rtk go run ./tools/stagingprobe \
  -api-base=https://api.staging.example \
  -probe-zoom \
  -zoom-webhook-secret="$ZOOM_WEBHOOK_SECRET_TOKEN"

rtk go run ./tools/stagingprobe \
  -api-base=https://api.staging.example \
  -probe-ai \
  -ai-bearer-token="$STAGING_AI_BEARER_TOKEN" \
  -ai-topic="Genesis 1:1 staging readiness probe"
```

The Zoom probe always verifies invalid-signature denial and, when a webhook secret is supplied, sends a signed no-op webhook event plus a signed `endpoint.url_validation` challenge. The AI probe is intentionally opt-in because it calls the deployed generation route and may invoke the configured provider.

For full Zoom staging evidence, use `tools/zoomprobe` after any live smoke runs. The dedicated Zoom probe validates captured artifacts for OAuth readiness, meeting creation or offline fallback, timeout/circuit-open fallback behavior, webhook delivery/signature checks, Zoom endpoint URL validation, duplicate webhook idempotency, and meeting-to-room mapping:

```bash
rtk go run ./tools/zoomprobe \
  -oauth-artifact-url=https://artifacts.staging.example/zoom/oauth.txt \
  -meeting-artifact-url=https://artifacts.staging.example/zoom/meeting-or-fallback.txt \
  -resilience-artifact-url=https://artifacts.staging.example/zoom/timeout-circuit-fallback.txt \
  -webhook-artifact-url=https://artifacts.staging.example/zoom/webhook-signature.txt \
  -webhook-validation-artifact-url=https://artifacts.staging.example/zoom/url-validation.txt \
  -duplicate-artifact-url=https://artifacts.staging.example/zoom/duplicate-idempotency.txt \
  -room-mapping-artifact-url=https://artifacts.staging.example/zoom/meeting-room-mapping.txt
```

The resilience artifact must include provider-timeout, circuit-open, `circuit_open_fallback`, fallback, and `offline://in-person` markers so staging evidence proves the failure path, not only successful meeting creation. The webhook signature artifact must prove Zoom `x-zm-signature` and `x-zm-request-timestamp` validation, stale replay `401` denial, invalid-signature `401`, and signed-event `200` behavior. The URL-validation artifact must prove `endpoint.url_validation` returned HTTP 200 with `plainToken` and `encryptedToken` markers. Duplicate-delivery proof must include a delivery ID, the same Zoom event, idempotent `200`, a single state mutation, and no duplicate side effects. Meeting-to-room mapping proof must show `meeting_external_id` resolving to `live_rooms.internal_room_id`, Redis room state mutation by internal room ID, unknown meeting ignore behavior, and no external meeting ID fallback. The probe only fetches HTTPS non-local artifact URLs, rejects localhost/loopback artifact hosts before fetching, rejects artifacts that expose obvious Zoom secret values such as `client_secret` or `ZOOM_WEBHOOK_SECRET_TOKEN`, and rejects artifacts marked as mock, placeholder, synthetic, stubbed, test-only, dry-run, or local-only evidence. A passing report includes `EXT-ZOOM-001` in `evidence_items`.
The recorder rejects `EXT-ZOOM-001` reports unless all seven Zoom probes pass, point at HTTPS non-local artifacts, and include verified marker summaries covering staging artifact provenance, OAuth, meeting/fallback, provider-timeout circuit fallback, Zoom signature headers with stale replay denial, URL validation, duplicate idempotency with one state mutation, and internal meeting-to-room mapping safeguards.
The strict release manifest validator also requires those Zoom marker summaries, so a generic `zoomprobe` report cannot satisfy `EXT-ZOOM-001`.

For full AI staging evidence, use `tools/aiprobe` after any live smoke runs. The dedicated AI probe validates captured artifacts for redacted provider/model configuration, JWT-claim authenticated generation, fail-closed timeout/degradation behavior, citation verification, and tenant-scoped `ai_request_logs`/`citation_trails` persistence:

```bash
rtk go run ./tools/aiprobe \
  -provider-artifact-url=https://artifacts.staging.example/ai/provider-config.txt \
  -generation-artifact-url=https://artifacts.staging.example/ai/generation.txt \
  -degradation-artifact-url=https://artifacts.staging.example/ai/degradation.txt \
  -citation-artifact-url=https://artifacts.staging.example/ai/citation-verification.txt \
  -audit-artifact-url=https://artifacts.staging.example/ai/audit-persistence.txt
```

The provider artifact must prove configured provider/model/endpoint/timeout/retry values with `OPENAI_API_KEY redacted` rather than exposing key material. The generation artifact must show the canonical route was called with authenticated JWT claims containing `organization_id` and `user_id`, and returned cited `generated_curriculum`. The degradation artifact must include provider timeout, retry exhaustion, fail-closed `503`, and `AI_ORCHESTRATION_ENGINE_FAULT` markers. The citation artifact must prove no-citation rejection, hallucinated-citation rejection, verified-citation acceptance, and `citation_trails`. The audit artifact must prove `ai_request_logs` and `citation_trails` persistence with request, organization, user, success/failure, verification, tenant RLS, and cross-tenant hidden markers. Provider and generation artifacts must be redacted; the probe only fetches HTTPS non-local artifact URLs, rejects localhost/loopback artifact hosts before fetching, rejects obvious API key or bearer-token leaks, and rejects artifacts marked as mock, placeholder, synthetic, stubbed, test-only, dry-run, or local-only evidence. A passing report includes `EXT-AI-001` in `evidence_items`.
The recorder rejects `EXT-AI-001` reports unless all five AI probes pass, point at HTTPS non-local artifacts, and include verified marker summaries covering staging artifact provenance, redacted provider config, JWT-claim authenticated generation, fail-closed timeout/degradation, citation verification, and tenant-RLS audit persistence.
The strict release manifest validator also requires those AI marker summaries, so a generic `aiprobe` report cannot satisfy `EXT-AI-001`.

After saving a probe report, attach it to an environment-specific evidence manifest with:

```bash
rtk node tools/record-staging-evidence.mjs \
  --manifest production-readiness/staging-evidence.staging.json \
  --probe-report artifacts/stagingprobe.json \
  --artifact artifacts/stagingprobe.json \
  --command "go run ./tools/stagingprobe -api-base=https://api.staging.example -web-base=https://app.staging.example"

STAGING_EVIDENCE_FILE=production-readiness/staging-evidence.staging.json \
  rtk node tools/validate-staging-evidence.mjs
```

The recorder only marks evidence IDs listed in a passing probe report's `evidence_items` array as `passed`, and it preserves validation requirements for the rest of the manifest.

For artifacts that are not emitted by a JSON probe, record a single explicit evidence item with `--item-id`:

```bash
rtk node tools/record-staging-evidence.mjs \
  --manifest production-readiness/staging-evidence.staging.json \
  --item-id SEC-SIGNOFF-001 \
  --artifact artifacts/release-signoff.txt \
  --command "security review signoff" \
  --summary "threat model approval complete; security/dependency_risk_register.md#DRR-001 dependency risk decision reviewed; residual risk review complete; owner/security approval recorded; release risk signoff approved"
```

Use this mode for human-reviewed release artifacts that do not have a dedicated JSON probe, such as owner/security signoff (`SEC-SIGNOFF-001`). Signoff summaries must explicitly include threat-model approval, `security/dependency_risk_register.md#DRR-001`, dependency-risk decision, residual-risk review, owner/security approval, and release-risk signoff markers. Probe-backed items, including CI, Terraform deployment, TLS, Kubernetes rollout, Secrets Store/IRSA, scoped DB user, tenant RLS, observability, web/mobile client smokes, Zoom, AI, load, rollback, and backup/restore evidence, must be recorded from their dedicated JSON probe reports so their strict artifact checks cannot be bypassed. The command marks only the named item as `passed`; blocked, failed, and accepted-risk decisions must still be written with owner/blocker or decision references so the validator can enforce them.

To record a real blocker or accepted residual risk without weakening the readiness claim:

```bash
rtk node tools/record-staging-evidence.mjs \
  --manifest production-readiness/staging-evidence.staging.json \
  --item-id DEPLOY-TF-001 \
  --status blocked \
  --owner platform \
  --blocker "waiting on AWS staging account access"

rtk node tools/record-staging-evidence.mjs \
  --manifest production-readiness/staging-evidence.staging.json \
  --item-id SEC-SIGNOFF-001 \
  --status accepted_risk \
  --decision-ref "security/dependency_risk_register.md#DRR-001" \
  --owner "security" \
  --accepted-by "release-owner" \
  --review-due-at "2026-07-25" \
  --expires-at "2026-08-25"
```

The validator requires `passed` entries to include evidence observed no later than the manifest timestamp, `blocked` and `failed` entries to include `owner` and `blocker`, and `accepted_risk` entries to include `decision_ref`, `owner`, `accepted_by`, `review_due_at`, and `expires_at`. Accepted-risk review dates must be on or before expiry, and expiry must not predate either the manifest/record timestamp or the current validation date. Strict release mode requires probe-backed passed evidence to reference HTTPS non-local JSON report artifacts, requires every probe-backed evidence family to declare semantic summary-marker checks, requires passed `SEC-SIGNOFF-001` evidence to include the security signoff markers above, permits accepted risk only for `SEC-SIGNOFF-001`, and only when it references `security/dependency_risk_register.md#DRR-001`.

For staged infrastructure, copy `build/terraform/backend.hcl.example` to an uncommitted backend config and run:

```bash
rtk terraform init -backend-config=backend.hcl
rtk terraform plan -var-file=terraform.tfvars
```

After capturing staging Terraform and Kubernetes artifacts, run the deployment probe so the evidence can be recorded into the manifest. Terraform mode requires remote S3 backend init output that names the state bucket, key, encrypted backend setting, and DynamoDB lock table, a staging plan containing EKS, node group, RDS, Redis, ECR, Kubernetes deployments, ingresses, HPA, PDB, SecretProviderClass manifest, and IAM role resources, plus either Terraform apply output or a deployment approval artifact that names the release candidate and deployed service version. The probe only fetches HTTPS non-local artifact URLs, rejects localhost/loopback hosts before fetching, and rejects mock, placeholder, synthetic, stubbed, test-only, dry-run, localhost, and loopback artifact content:

```bash
rtk go run ./tools/deploymentprobe \
  -probe-terraform \
  -terraform-init-url=https://artifacts.staging.example/deploy/terraform-init.txt \
  -terraform-plan-url=https://artifacts.staging.example/deploy/terraform-plan.txt \
  -terraform-apply-url=https://artifacts.staging.example/deploy/terraform-apply-or-approval.txt
```

Kubernetes mode requires rollout status and workload resource artifacts proving API, web, and Rust deployments are rolled out, ready, and available, plus service, TLS ingress, HPA min/max replica and target settings, PDB min-availability, readiness/liveness probes, rolling-update `maxUnavailable=0`, and SecretProviderClass workload wiring. Capture resource artifacts with enough detail, such as `kubectl get deploy,svc,ingress,hpa,pdb,secretproviderclass -o yaml`, rather than a terse table that hides probes and rollout strategy:

```bash
rtk go run ./tools/deploymentprobe \
  -probe-kubernetes \
  -k8s-rollout-url=https://artifacts.staging.example/deploy/kubectl-rollout-status.txt \
  -k8s-resources-url=https://artifacts.staging.example/deploy/kubectl-resources.txt
```

Passing reports include `DEPLOY-TF-001`, `DEPLOY-K8S-001`, or both in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`. This validates captured deployment artifacts; it does not replace `tools/stagingprobe` TLS/readiness checks against the deployed API and web hostnames.
The recorder rejects `DEPLOY-TF-001` unless the Terraform deployment probe includes exactly the remote-backend init, staging plan, and apply-or-approval probes, all passing with HTTP 200 from HTTPS non-local artifact URLs, and each probe summary includes the `staging artifact` provenance marker plus the verified deployment markers from `tools/deploymentprobe`, including remote-state locking/encryption and workload resource types. It rejects `DEPLOY-K8S-001` unless rollout/resource artifact summaries include `staging artifact` provenance and prove the API, web, Rust, service, TLS ingress, HPA, PDB, health probe, rolling-update, and SecretProviderClass markers.
The strict release manifest validator also requires those deployment marker summaries, so a generic `deploymentprobe` JSON URL is not enough for `DEPLOY-TF-001` or `DEPLOY-K8S-001` readiness.

The Terraform skeleton requires an ACM certificate ARN for public ALB ingresses:

```hcl
ingress_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
ingress_ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
```

Both API and web ingresses redirect HTTP to HTTPS and attach the configured certificate and SSL policy. Production readiness still requires DNS validation, ACM issuance, staging `plan`/`apply`, and TLS probe evidence against the deployed hostnames.

The Go API exposes `/live` for process liveness and `/ready` for dependency readiness. Terraform maps API liveness/readiness probes to those endpoints and maps the public API ALB health check to `/ready`. The Rust scripture engine binds to `0.0.0.0:50051` by default for pod-to-pod gRPC reachability, can be overridden with `RUST_ENGINE_BIND_ADDRESS`, serves the standard gRPC health checking service, and exposes HTTP `/healthz` on `RUST_ENGINE_METRICS_ADDRESS` for Kubernetes probes that cannot present mTLS credentials. Local development can default the Go API's `GRPC_ENGINE_ADDRESS` to `localhost:50051`, but `DEPLOYMENT_ENVIRONMENT=staging|production|prod` requires an explicit address plus `GRPC_ENGINE_SHARED_SECRET`, `GRPC_ENGINE_TLS_CA_PEM`, `GRPC_ENGINE_TLS_CLIENT_CERT_PEM`, `GRPC_ENGINE_TLS_CLIENT_KEY_PEM`, and `GRPC_ENGINE_TLS_SERVER_NAME`; Terraform supplies these from Secrets Manager and uses `scriptureforge-rust-engine:50051`.

For deployed Rust engine evidence, run the gRPC and metrics probe from a network location that can reach the Rust service:

```bash
rtk go run ./tools/rustprobe \
  -grpc-address=scriptureforge-rust-engine:50051 \
  -grpc-ca-file=/run/secrets/grpc-ca.pem \
  -grpc-client-cert-file=/run/secrets/grpc-client-cert.pem \
  -grpc-client-key-file=/run/secrets/grpc-client-key.pem \
  -grpc-server-name=scriptureforge-rust-engine \
  -metrics-url=http://scriptureforge-rust-engine:9102/metrics \
  -api-metrics-url=https://api.staging.example/metrics \
  -timeout=5s
```

The report includes `RUST-GRPC-001` in `evidence_items`, verifies the standard gRPC health service reports `SERVING` over mTLS, requires the Rust metrics endpoint to expose the embedding/vector-search request and failure counters, and requires the deployed Go API `/metrics` endpoint to show a successful `rust_engine` `vector_search` dependency operation after a staging API flow has invoked the Rust engine. The probe requires CA/client certificate/client key/server-name inputs, rejects local/loopback gRPC targets, malformed gRPC addresses, missing metrics URLs, and local/loopback metrics URLs before issuing release-evidence probes. Attach the resulting JSON with `tools/record-staging-evidence.mjs`.
The recorder rejects `RUST-GRPC-001` reports that use local loopback targets, omit the Rust metrics probe, omit the API integration metrics probe, or omit verified marker summaries for gRPC health, the ScriptureForge health service name, `SERVING`, `scriptureforge_rust_engine_embedding_requests_total`, `scriptureforge_rust_engine_embedding_failures_total`, `scriptureforge_rust_engine_vector_search_requests_total`, `scriptureforge_rust_engine_vector_search_failures_total`, Prometheus metrics, `Go API rust_engine vector_search success`, `scriptureforge_dependency_operations_total`, and `scriptureforge_dependency_operation_duration_seconds_sum`; release evidence must include deployed gRPC health plus complete Rust and API-side operational metrics proof.
The strict release manifest validator also requires those Rust marker summaries, so a generic `rustprobe` report cannot satisfy `RUST-GRPC-001`.

For deployed tenant isolation evidence through the public API, run the tenant probe with two staging bearer tokens: one token that owns the created journal entry and room, and a second token from another user or tenant that must not be able to read those resources.

```bash
rtk go run ./tools/tenantprobe \
  -api-base=https://api.staging.example \
  -owner-token="$TENANT_PROBE_OWNER_TOKEN" \
  -blocked-token="$TENANT_PROBE_BLOCKED_TOKEN" \
  -db-rls-artifact-url=https://artifacts.staging.example/data/rls-db-proof.txt \
  -timeout=5s
```

The probe creates an encrypted journal payload and a room, proves the owner token can directly read the created journal, proves the owner journal list contains that same created entry, proves the owner can list/state-check the room, proves the blocked token receives `404` for the direct journal read, proves blocked journal and room lists exclude the created resources, and proves blocked room-state access is denied. The DB/RLS artifact must be redacted, identify itself as a staging artifact, and prove the app database principal is non-superuser, `app.current_org_id` is set, row security is active and forced across all tenant-scoped tables (`organizations`, `users`, `scripture_texts`, `refresh_tokens`, `journal_entries`, `live_rooms`, `room_participants`, `ai_request_logs`, and `citation_trails`), same-tenant reads are visible, cross-tenant reads are hidden, and cross-tenant writes are denied. The probe requires HTTPS non-local API and DB/RLS artifact URLs before any request, rejects localhost/loopback targets before fetching, and rejects obvious database secret leaks plus DB/RLS artifacts marked as mock, placeholder, synthetic, stubbed, test-only, dry-run, or local-only evidence. The report includes `DATA-RLS-001` in `evidence_items` so it can be attached with `tools/record-staging-evidence.mjs`.
The recorder rejects `DATA-RLS-001` reports that target local/non-HTTPS APIs, omit the owner/blocked journal or room probes, do not return `201` for owner journal/room create, `200` for owner direct journal read, owner journal list visibility, owner room list/state, and blocked list probes, `404` for blocked direct journal read, `403` for blocked room state, omit the verified same-tenant/cross-tenant API proof markers from probe summaries, do not include an HTTPS non-local database RLS artifact probe, or omit the staging artifact and verified DB/RLS marker list from that probe summary.
The strict release manifest validator also requires those tenant API and database RLS marker summaries, so a generic `tenantprobe` report cannot satisfy `DATA-RLS-001`.

For deployed mobile readiness evidence, run the mobile probe against captured EAS/native-device artifacts. This is separate from `mobile npm run smoke` and `tools/verify-journal-crypto.mjs`: the local mobile smoke now covers AES-GCM round-trip, tamper rejection, non-extractable keys, disposed-key handles, and native-required fail-closed behavior under the local WebCrypto-compatible runtime; the repo verifier guards that smoke coverage, implementation shape, and the `react-native-quick-crypto` provider selection path with a local provider harness. `tools/mobileprobe` still requires native/EAS proof that the `react-native-quick-crypto` AES-GCM path works outside test shims and that mobile API/WS config points at staging:

```bash
rtk go run ./tools/mobileprobe \
  -eas-artifact-url=https://artifacts.staging.example/mobile/eas-build.txt \
  -native-crypto-smoke-url=https://artifacts.staging.example/mobile/native-crypto-smoke.txt \
  -staging-config-proof-url=https://artifacts.staging.example/mobile/staging-config.txt
```

The EAS/native-device artifact must include Android and iOS build completion, native-device validation, installed-app proof, `release channel staging`, and `expo profile staging` markers; dry-run, simulator-only, mock, and placeholder artifacts are rejected. The native crypto artifact must include `react-native-quick-crypto`, `AES-GCM`, round-trip success, tamper rejection, non-extractable key proof, key disposal proof, and disposed-handle rejection markers. It must not be produced by Node/WebCrypto shims, Expo Crypto placeholders, mocks, or placeholder crypto. The probe only fetches HTTPS non-local artifact URLs and rejects localhost/loopback artifact hosts before fetching. The mobile runtime config rejects local or insecure endpoints whenever `EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true` or `EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging|production|prod`, so the config proof must include HTTPS and WSS staging endpoints, set `EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true`, include `EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging`, and must not use localhost, `EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=false`, or the old hardcoded `wss://api.scriptureforge.com` value. Passing reports include `CLIENT-MOBILE-001` in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`.
The recorder rejects `CLIENT-MOBILE-001` reports unless all three mobile probes pass, point at HTTPS non-local artifacts, and include verified marker summaries for installed staging app/EAS output, native AES-GCM crypto smoke, key lifecycle cleanup, and strict staging API/WS configuration.
The strict release manifest validator also requires those mobile marker summaries, so a generic `mobileprobe` report cannot satisfy `CLIENT-MOBILE-001`.

For deployed secret and database principal evidence, run the security probe with redacted staging artifacts and the staged app `DATABASE_URL`. The secret-sync mode expects HTTPS non-local artifacts for the IRSA service account plus trust policy, `SecretProviderClass`, synced secret metadata, scoped workload IAM policy, and scoped access test. It rejects localhost/loopback artifact hosts before fetching and rejects obvious plaintext DSNs, API keys, private keys, and secret values in metadata artifacts:

```bash
rtk go run ./tools/securityprobe \
  -probe-secrets \
  -service-account-url=https://artifacts.staging.example/k8s/serviceaccount-api.yaml \
  -secret-provider-url=https://artifacts.staging.example/k8s/secret-provider-class.yaml \
  -synced-secret-url=https://artifacts.staging.example/k8s/runtime-secret-redacted.yaml \
  -iam-policy-url=https://artifacts.staging.example/aws/app-secrets-policy.json \
  -access-test-url=https://artifacts.staging.example/aws/app-secrets-access-test.txt
```

The service-account artifact must prove both the `eks.amazonaws.com/role-arn` annotation and `sts:AssumeRoleWithWebIdentity` trust policy. The SecretProviderClass artifact must prove AWS provider mapping through `objects`, `objectName`, `objectType=secretsmanager`, `objectAlias`, `jmesPath`, `secretObjects`, and `type=Opaque` markers for the runtime secret keys. The synced-secret metadata artifact must prove redacted `Opaque` metadata for `DATABASE_URL`, `JWT_SECRET_KEY`, `OPENAI_API_KEY`, and `ZOOM_WEBHOOK_SECRET_TOKEN`, plus `stringData absent` and `managed by secrets-store.csi.k8s.io`; it must not contain secret values. The IAM policy artifact must prove scoped Secrets Manager resources and no wildcard resources. The access-test artifact must prove the workload role can read configured ScriptureForge secret ARNs and receives `AccessDenied` for an unscoped secret. This is separate from policy-shape review so `SEC-SECRETS-001` includes observed allow/deny behavior.

The scoped database user mode connects with `STAGING_DATABASE_URL`, does not emit the URL, rejects root/admin/reserved principals, and verifies the connected role is not superuser, `CREATEROLE`, or `CREATEDB`:

```bash
STAGING_DATABASE_URL="$DATABASE_URL" \
  rtk go run ./tools/securityprobe -probe-db-user
```

Passing reports include `SEC-SECRETS-001`, `SEC-DBUSER-001`, or both in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`. This proves the observed staging artifacts and database principal; it still needs clean CI secret scanning and owner review of cloud-side access roles.
The recorder rejects `SEC-SECRETS-001` unless all five secret/IRSA probes pass against HTTPS non-local artifacts and each probe summary includes the verified artifact markers from `tools/securityprobe`, including IRSA trust-policy markers, AWS SecretProviderClass object-sync markers, synced-secret redaction markers, and scoped/no-wildcard IAM policy markers; it rejects `SEC-DBUSER-001` unless the database probe target stays redacted and the live connection summary proves `superuser=false`, `createrole=false`, and `createdb=false`.
The strict release manifest validator also requires those secret-handling and scoped database-user marker summaries, so generic `securityprobe` reports cannot satisfy `SEC-SECRETS-001` or `SEC-DBUSER-001`.

For deployed abuse/rate-limit evidence, run the abuse probe against staging with a valid bearer token and allowed web origin. The probe repeats auth login, auth refresh, account-scoped login, AI, journal, rooms, and room-stream requests until each profile returns `429` with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers. The account-scoped login probe sends a stable normalized organization/email payload while rotating forwarded client IP headers, the refresh probe reuses a stable opaque refresh token body to prove token-scoped throttling, and the room-stream profile sends a real WebSocket upgrade request so `ABUSE-LIMIT-001` cannot be satisfied by a plain HTTP GET to the socket path:

```bash
rtk go run ./tools/abuseprobe \
  -api-base=https://api.staging.example \
  -bearer-token="$STAGING_ABUSE_BEARER_TOKEN" \
  -origin=https://app.staging.example \
  -config-artifact-url=https://artifacts.staging.example/abuse/abuse-limit-config.txt \
  -attempts=35
```

Set staging `ABUSE_LIMIT_*_REQUESTS` values low enough for the run window, or raise `-attempts` above the deployed limits. The in-process limiter also honors `ABUSE_LIMIT_MAX_BUCKETS` to bound active identity buckets; when the cap is reached, new identities fall into a shared per-profile overflow bucket instead of growing memory without bound. Login applies an account-scoped `ABUSE_LIMIT_AUTH_ACCOUNT_*` bucket keyed by a hash of normalized `organization_id` plus email, and refresh applies the same profile to a hash of normalized `organization_id` plus refresh-token hash, so rotating source IPs cannot bypass repeated attempts against one account or token and metrics do not expose account identifiers. The config artifact must be a redacted deployment/config snapshot showing `staging artifact`, active `ABUSE_LIMIT_AUTH_*`, `ABUSE_LIMIT_AUTH_ACCOUNT_*`, `ABUSE_LIMIT_AI_*`, `ABUSE_LIMIT_JOURNAL_*`, `ABUSE_LIMIT_ROOMS_*`, `ABUSE_LIMIT_WEBSOCKET_*`, `ABUSE_LIMIT_MAX_BUCKETS`, `TRUST_PROXY_HEADERS`, `X-Forwarded-For`, `X-Real-IP`, and `redacted` markers used for the probed release. A passing report includes `ABUSE-LIMIT-001` in `evidence_items`, `config_artifact_verified=true`, and a `config_artifact_summary` marker list. The probe and recorder reject local, loopback, non-HTTPS, missing-profile, missing-config-artifact, missing-header, markerless, mock/dry-run/local-only, or obvious secret-leaking abuse reports so weak artifacts cannot be recorded as production evidence. The account-scoped login profile summary must include verified `account-scoped login` and `rotating forwarded client IP` markers, the refresh profile summary must include a verified `refresh token` marker, and the WebSocket profile summary must include a verified `websocket upgrade` marker. The probe requires HTTPS non-local API, origin, and config-artifact hosts and does not weaken TLS validation for staging.

For deployed rollback and backup/restore evidence, run the resilience probe against captured staging artifacts and readiness/smoke endpoints. Rollback mode requires API readiness before rollback with `service_version`, `deployment_environment`, `pre_rollback_version`, and `release_candidate`, rollout undo/status output naming `previous_revision`, `target_revision`, and `scriptureforge-api`, API readiness after rollback with `post_rollback_version`, `rolled_back_from`, and `rolled_back_to`, and AI/Zoom degradation drill evidence showing `AI_ORCHESTRATION_ENGINE_FAULT`, Zoom `offline://in-person` fallback, `zoom circuit open`, and `non-AI routes healthy`:

```bash
rtk go run ./tools/resilienceprobe \
  -probe-rollback \
  -api-ready-before-url=https://artifacts.staging.example/rollback/api-ready-before.json \
  -rollout-artifact-url=https://artifacts.staging.example/rollback/kubectl-rollout-undo.txt \
  -api-ready-after-url=https://artifacts.staging.example/rollback/api-ready-after.json \
  -degradation-drill-url=https://artifacts.staging.example/rollback/degradation-drill.txt
```

Backup mode requires encrypted KMS snapshot creation with `snapshot_id`, retention, automated-backup, source-cluster, and `rpo_minutes` evidence, restore drill evidence with `restore_job_id`, restored endpoint, source `snapshot_id`, checksum, isolated-restore, `rto_minutes`, and `restore_duration_minutes` proof, and an application smoke proof against the restored database that covers auth, tenant/RLS, migration version, journal behavior, and no plaintext journal persistence:

```bash
rtk go run ./tools/resilienceprobe \
  -probe-backup \
  -backup-artifact-url=https://artifacts.staging.example/backup/snapshot.txt \
  -restore-artifact-url=https://artifacts.staging.example/backup/restore.txt \
  -restored-smoke-url=https://artifacts.staging.example/backup/restored-db-smoke.json
```

Passing reports include `DR-ROLLBACK-001`, `DR-BACKUP-001`, or both in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`. This validates captured drill evidence; it does not perform the destructive rollback or restore action by itself.
The probe only fetches HTTPS non-local staging endpoints or artifact URLs, rejects localhost/loopback hosts before fetching, and rejects artifacts marked as mock, placeholder, synthetic, stubbed, test-only, dry-run, or local-only evidence. The recorder rejects resilience reports unless the requested rollback and backup evidence items include exactly their required passing probes with HTTP 200 responses from HTTPS non-local staging endpoints or artifact URLs, and each probe summary includes staging artifact provenance plus the verified version-linkage, degradation, snapshot/restore-linkage, RPO/RTO, restore-duration, restored-RLS, and no-plaintext markers from `tools/resilienceprobe`.
The strict release manifest validator also requires those rollback, degradation, backup, restore, and restored-database smoke marker summaries, so generic `resilienceprobe` reports cannot satisfy `DR-ROLLBACK-001` or `DR-BACKUP-001`.

For deployed observability evidence, run the observability probe against staging telemetry surfaces. The OTEL mode requires collector config proof with OTLP receiver/exporter/service pipelines, API metrics that include HTTP request count/duration plus successful `rust_engine` `vector_search` dependency count/duration markers, Rust embedding/vector-search request and failure counters, a trace backend query showing the same trace across Go API and Rust engine services, and a log backend query preserving the same `trace_id`, service/version/environment fields, plus verified tenant principal markers (`tenant_id`, `user_id`, and `role`) from protected API routes:

```bash
rtk go run ./tools/observabilityprobe \
  -probe-otel \
  -collector-config-url=https://observability.staging.example/collector-config \
  -api-metrics-url=https://api.staging.example/metrics \
  -rust-metrics-url=http://scriptureforge-rust-engine:9102/metrics \
  -trace-query-url=https://traces.staging.example/search?trace_id=$STAGING_TRACE_ID \
  -log-query-url=https://logs.staging.example/search?trace_id=$STAGING_TRACE_ID \
  -trace-id="$STAGING_TRACE_ID"
```

The generated OTEL report persists `trace_id`, and the staging evidence recorder rejects `OBS-OTEL-001` artifacts unless both the trace backend and log backend probe targets carry that same trace ID.

Alert/dashboard mode requires deployed dashboard panels for API request rate, duration, Rust engine metrics, and trace-correlated logs, loaded alert rules for high error rate, traffic absence, auth failure spikes, abuse-limit spikes, route latency, dependency failures, journal write failures, room stream failures, and Rust engine failures, a delivered test alert through Alertmanager, and 30-day trace/log/metric retention proof endpoints or exported artifacts served through URLs:

```bash
rtk go run ./tools/observabilityprobe \
  -probe-alerts \
  -dashboard-url=https://grafana.staging.example/d/scriptureforge-overview \
  -alert-rules-url=https://prometheus.staging.example/api/v1/rules \
  -alertmanager-url=https://alertmanager.staging.example/api/v2/status \
  -retention-url=https://observability.staging.example/retention-proof
```

The report includes `OBS-OTEL-001`, `OBS-ALERT-001`, or both in `evidence_items` only for the requested passing modes. The OTEL probe requires the trace and log backend query URLs to include the supplied `-trace-id`, so broad search endpoints cannot satisfy trace-correlation evidence by coincidence. The probe rejects local/loopback telemetry hosts and artifacts marked mock, placeholder, synthetic, stubbed, test-only, dry-run, or local-only. This is still proof collection, not a substitute for importing dashboards, firing a test alert, and confirming the staging telemetry backend retains traces, logs, and metrics for at least 30 days.
The probe and recorder reject observability reports unless the requested OTEL and alert evidence items include exactly their required passing probes with HTTP 200 responses from non-local HTTP(S) staging telemetry surfaces and verified marker summaries for collector config, API HTTP metrics, API-side `rust_engine` vector-search dependency metrics, Rust embedding/vector-search request and failure counters, trace/log correlation, dashboard import, the full production alert-rule suite, alert delivery, and retention.
The strict release manifest validator also requires those observability marker summaries, so generic `observabilityprobe` reports cannot satisfy `OBS-OTEL-001` or `OBS-ALERT-001`.

## Performance Harness

`tools/loadtest` is a small HTTP load harness for repeatable local and staging evidence. The CI smoke path uses an in-process `/health` endpoint so the executable and threshold reporting stay covered without requiring deployed services:

```bash
rtk go run ./tools/loadtest -self-test -duration=2s -concurrency=8 -min-rps=100 -max-p99=200ms
```

For staging readiness, run the same harness against the deployed API health endpoint and raise thresholds to match the architecture target:

```bash
rtk go run ./tools/loadtest \
  -target=https://api.example.com/health \
  -http-replica-artifact-url=https://artifacts.staging.example/load/http-replicas.txt \
  -dependency-telemetry-artifact-url=https://artifacts.staging.example/load/dependency-telemetry.txt \
  -release-candidate="$RELEASE_CANDIDATE" \
  -service-version="$SERVICE_VERSION" \
  -duration=5m \
  -concurrency=512 \
  -min-rps=5000 \
  -max-p99=200ms
```

The command emits JSON with request count, failures, RPS, P50/P95/P99, `evidence_profile`, production target RPS/P99 metadata for staging targets, explicit `threshold_failures`, threshold status, release metadata, `result_summary` verified markers, and same-run artifact URLs for ingress/API replica distribution plus database/Redis telemetry. A passing local self-test does not prove the production 5,000 req/s target; that requires a staging run against real ingress, API, network, and dependency infrastructure. The harness emits `PERF-HTTP-001` only for non-local HTTPS targets, rejects local/loopback performance artifact URLs before the run, fetches the replica and dependency telemetry artifacts for required staging markers, rejects weak or mock artifact content, and requires `release_candidate` plus `service_version` markers in those artifacts. The staging evidence recorder refuses `PERF-HTTP-001` unless the report targets HTTPS, is not local/self-test, sets `min_rps` to at least `5000`, sets `max_p99_ms` to at most `200`, the observed `rps`/`p99_ms` meet those same thresholds, includes non-empty `release_candidate` and `service_version` fields, includes HTTPS non-local artifacts for replica distribution and dependency telemetry, and includes a `result_summary` marker list tying the profile, target, thresholds, observed RPS/P99, release metadata, artifact fields, and HTTP artifact verification markers together.

External HTTP load reports include `PERF-HTTP-001` in `evidence_items`, so a passing staging report can be attached with `tools/record-staging-evidence.mjs`.

For local WebSocket room-stream coverage, the harness can start an in-process `SocketConnection`, validate room membership through the production handler path, send sequenced room events, and measure accepted-broadcast latency:

```bash
rtk go run ./tools/loadtest -websocket-self-test -concurrency=8 -ws-events-per-client=5 -min-rps=20 -max-p99=200ms
```

This proves the local socket lifecycle and broadcast harness, not multi-instance production fan-out. Final readiness still requires a staging WebSocket load run against real API replicas and Redis.
The backend room stream tests also prove handler-level concurrent sender behavior: accepted WebSocket events receive contiguous sequences, broadcast back to participants, and increment low-cardinality Redis append metrics.

WebSocket origin policy is deliberately environment-sensitive: local development can use localhost/no-origin fallback when `ALLOWED_WS_ORIGINS` is unset, but `DEPLOYMENT_ENVIRONMENT=staging|production|prod` requires `ALLOWED_WS_ORIGINS` and fails upgrades closed when it is missing.

For staging WebSocket evidence against a deployed room stream, run the harness against a real `wss://` endpoint with a room member token and allowed browser origin:

```bash
rtk go run ./tools/loadtest \
  -websocket \
  -target=wss://api.example.com/api/v1/rooms/stream/room-id \
  -ws-room-id=room-id \
  -ws-token="$ACCESS_TOKEN" \
  -ws-origin=https://app.example.com \
  -ws-replica-artifact-url=https://artifacts.staging.example/load/ws-replicas.txt \
  -ws-reconnect-artifact-url=https://artifacts.staging.example/load/ws-reconnect.txt \
  -ws-polling-artifact-url=https://artifacts.staging.example/load/ws-polling.txt \
  -redis-telemetry-artifact-url=https://artifacts.staging.example/load/redis-telemetry.txt \
  -release-candidate="$RELEASE_CANDIDATE" \
  -service-version="$SERVICE_VERSION" \
  -concurrency=128 \
  -ws-events-per-client=20 \
  -min-rps=500 \
  -max-p99=200ms
```

The staging WebSocket command uses the same JSON report shape as HTTP load tests and verifies accepted event broadcasts over real upgrade/origin/auth behavior. For WSS staging targets, the harness requires `-ws-token`, a non-local HTTPS `-ws-origin`, non-local HTTPS replica/Redis artifacts, plus non-local HTTPS reconnect and HTTP polling fallback artifacts. It fetches those artifacts before emitting evidence and requires marker proof for API replica distribution, reconnect after disconnect, polling `/api/v1/rooms/state` latest-state fallback, Redis contiguous/no-duplicate/no-skipped sequence telemetry, and the same `release_candidate` plus `service_version` linkage. It then persists `ws_authenticated=true`, `ws_origin`, release metadata, artifact URLs, and `*_artifact_verified` markers in the JSON report. A production readiness claim still needs the run output captured against real API replicas and Redis.

External WebSocket load reports include `PERF-WS-001` and `DATA-REDIS-001` in `evidence_items`, so passing staging reports can be attached to the evidence manifest with the same recorder. Local `-self-test`, `-websocket-self-test`, and non-WSS local-target reports intentionally omit `evidence_items` so they cannot be mistaken for staging proof. The harness rejects local/loopback WebSocket evidence artifact URLs before dialing. The recorder also requires `PERF-WS-001` reports to target WSS, avoid local/self-test targets, prove `ws_authenticated=true`, include non-local HTTPS `ws_origin`, bind the run to structured `ws_user_id` and `ws_organization_id` values, set `min_rps` to at least `500`, set `max_p99_ms` to at most `200`, include observed results meeting those thresholds, include non-empty `release_candidate` and `service_version` fields, include HTTPS non-local artifacts proving API replica distribution, reconnect behavior, and HTTP polling fallback, and include a `result_summary` marker list covering profile, WSS target, authenticated HTTPS origin, tenant principal, thresholds, observed RPS/P99, release metadata, sequence proof, reconnect/polling proof, artifact fields, and artifact verification markers. `DATA-REDIS-001` cannot be recorded from load evidence unless paired with `PERF-WS-001`, an HTTPS non-local Redis telemetry artifact from the same run, contiguous sequence fields, release metadata, matching tenant principal markers, and matching Redis sequence plus `redis_telemetry_artifact_verified` markers in the summary.
