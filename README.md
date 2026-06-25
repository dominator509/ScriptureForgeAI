# ScriptureForgeAI

## Local Remediation Prerequisites

The audit remediation work targets the repo-current toolchain:

- Go toolchain `1.24.3`
- Node.js with `npm ci` run inside `web/`
- Rust stable for `services/scripture-engine`; protobuf generation uses vendored `protoc` via Cargo build dependencies, so a separate `protoc` binary is optional for local builds.
- Terraform `1.6+`

Useful validation commands:

```bash
rtk go test ./...
rtk npm run typecheck
rtk npm run build
rtk cargo test
rtk terraform init -backend=false
rtk terraform fmt -check
rtk terraform validate
rtk node tools/validate-observability.mjs
rtk node tools/validate-secret-hygiene.mjs
rtk node tools/validate-deployment-skeleton.mjs
rtk node tools/validate-staging-evidence.mjs
rtk node tools/validate-security-artifacts.mjs
rtk node tools/verify-journal-crypto.mjs
```

OpenTelemetry tracing is optional for local runs and enabled when an OTLP/HTTP collector endpoint is configured:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.observability:4318
OTEL_EXPORTER_OTLP_INSECURE=true
OTEL_SERVICE_NAME=scriptureforge-api
SERVICE_VERSION=2026.06.25
DEPLOYMENT_ENVIRONMENT=staging
```

The Terraform skeleton maps the same production values through `service_version`, `otel_exporter_otlp_endpoint`, and `otel_exporter_otlp_insecure` so the API deployment can emit traces once a collector is available.

The Rust scripture engine emits JSON startup/request/error logs, extracts W3C `traceparent` metadata from gRPC requests into `trace_id` log fields, exposes Prometheus text metrics on `RUST_ENGINE_METRICS_ADDRESS` defaulting to `0.0.0.0:9102`, and receives `OTEL_SERVICE_NAME`, `SERVICE_VERSION`, `DEPLOYMENT_ENVIRONMENT`, and `OTEL_EXPORTER_OTLP_ENDPOINT` through Terraform. This is baseline Rust gRPC observability and log/metric correlation, not proof that a deployed OTLP collector is receiving Rust spans.

Runtime secrets are modeled through AWS Secrets Manager ARNs in `app_secret_arns`. The skeleton uses IRSA plus the Secrets Store CSI driver to sync `DATABASE_URL`, `JWT_SECRET_KEY`, `OPENAI_API_KEY`, and Zoom credential variables into API/Rust pods without committing plaintext secret values. The `database_url` secret should point at an application database user, not the RDS root user. A staging cluster must already have the Secrets Store CSI driver and AWS provider installed before apply.

`tools/validate-deployment-skeleton.mjs` verifies the local Terraform skeleton keeps the expected remote state, TLS ingress, IRSA/Secrets Store CSI, runtime secret references, health/readiness probes, Rust gRPC probe, OTLP env wiring, resource request/limit controls, pod disruption budgets, topology spread constraints, horizontal pod autoscalers, and web/API image/config boundaries. It is a drift guard for the skeleton, not live AWS deployment proof.

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

Use `--format json` when a release handoff needs machine-readable counts and evidence requirements. The command exits non-zero until every strict-release item is passed, except `SEC-SIGNOFF-001` may be recorded as `accepted_risk`.

Before claiming production readiness, run the same validator in strict release mode:

```bash
STAGING_EVIDENCE_FILE=production-readiness/staging-evidence.staging.json \
  rtk node tools/validate-staging-evidence.mjs --strict-release
```

Strict mode rejects placeholder release candidates plus any `pending_external`, `blocked`, or `failed` item. It also rejects `accepted_risk` outside `SEC-SIGNOFF-001`, so operational proof items such as deployment, TLS, RLS, observability, load, and rollback must be `passed`.

After strict evidence validation passes, run the final claim verifier from the release checkout:

```bash
STAGING_EVIDENCE_FILE=production-readiness/staging-evidence.staging.json \
LOCAL_GATE_REPORT_FILE=artifacts/local-gate-report.json \
  rtk node tools/verify-production-readiness.mjs
```

The verifier reruns strict manifest validation, validates the full non-dry-run local gate report, requires a clean git worktree, requires the branch to be neither ahead nor behind upstream, requires `release_candidate` to equal the current `git rev-parse HEAD` SHA, and requires the local gate report `git_head` to match that same SHA.

The CI workflow is also guarded against gate drift:

```bash
rtk node tools/validate-ci-workflow.mjs
```

That validator requires the security workflow to retain the Go, Postgres/RLS, load harness, evidence tooling, observability, secret hygiene, deployment skeleton, web, mobile, Rust, Terraform, TruffleHog, and CI release-evidence gates.

For repeatable local gate evidence, run the local gate runner:

```bash
rtk node tools/run-local-gates.mjs --report artifacts/local-gate-report.json
```

The runner executes the repo-local Go, web audit/smoke/typecheck/build, mobile high-severity audit/smoke/build-compatible, Rust, Terraform, observability, deployment skeleton, staging evidence, CI workflow, security artifact, secret hygiene, journal crypto, and tooling test gates and writes a JSON report stamped with the current `git_head`. Use `--only go-test,go-vet` for a focused subset, `--dry-run` to print a pass-shaped plan without executing commands, and `--continue-on-failure` when you want one report containing every failure instead of stopping at the first failed gate.

Validate a full non-dry-run report before treating it as local readiness evidence:

```bash
rtk node tools/validate-local-gate-report.mjs --report artifacts/local-gate-report.json
```

Focused or dry-run reports can be checked during development with `--allow-subset` or `--allow-dry-run`, but those relaxed modes do not satisfy the full local gate evidence requirement.

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

The report emits `SRC-CI-001` in `evidence_items` only when the artifact proves the exact release commit completed the required CI gates successfully and does not include failed/cancelled/stale/dirty-run markers.

The workflow writes this artifact with `tools/write-ci-release-evidence.mjs` after the required local gates and TruffleHog step complete, immediately validates the local file with `tools/ciprobe`, and then uploads it as the `ci-release-evidence` artifact. The artifact names the full commit SHA, workflow, job, run URL, successful conclusion, and required gate markers so it can be recorded into the staging evidence manifest with `tools/record-staging-evidence.mjs`.

`tools/stagingprobe` emits a JSON probe report for deployed HTTPS readiness checks that can be attached to the staging evidence manifest for `DEPLOY-TLS-001`, `DEPLOY-K8S-001`, and `CLIENT-WEB-001`:

```bash
rtk go run ./tools/stagingprobe \
  -api-base=https://api.staging.example \
  -web-base=https://app.staging.example \
  -timeout=5s
```

The probe requires HTTPS targets, checks API `/live` and `/ready`, checks the web root, records TLS version/certificate expiry, and verifies HTTP-to-HTTPS redirects. It is an evidence collector for deployed services, not a substitute for Terraform apply, Kubernetes rollout, load, observability, or external-service proof.

Optional external-service probes can attach evidence for `EXT-ZOOM-001` and `EXT-AI-001`:

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

The Zoom probe always verifies invalid-signature denial and, when a webhook secret is supplied, sends a signed no-op webhook event. The AI probe is intentionally opt-in because it calls the deployed generation route and may invoke the configured provider.

For full Zoom staging evidence, pair `tools/stagingprobe -probe-zoom` with `tools/zoomprobe`. The dedicated Zoom probe validates captured artifacts for OAuth readiness, meeting creation or offline fallback, timeout/circuit-open fallback behavior, webhook delivery/signature checks, duplicate webhook idempotency, and meeting-to-room mapping:

```bash
rtk go run ./tools/zoomprobe \
  -oauth-artifact-url=https://artifacts.staging.example/zoom/oauth.txt \
  -meeting-artifact-url=https://artifacts.staging.example/zoom/meeting-or-fallback.txt \
  -resilience-artifact-url=https://artifacts.staging.example/zoom/timeout-circuit-fallback.txt \
  -webhook-artifact-url=https://artifacts.staging.example/zoom/webhook-signature.txt \
  -duplicate-artifact-url=https://artifacts.staging.example/zoom/duplicate-idempotency.txt \
  -room-mapping-artifact-url=https://artifacts.staging.example/zoom/meeting-room-mapping.txt
```

The resilience artifact must include timeout, circuit-open, fallback, and `offline://in-person` markers so staging evidence proves the failure path, not only successful meeting creation. The probe rejects artifacts that expose obvious Zoom secret values such as `client_secret` or `ZOOM_WEBHOOK_SECRET_TOKEN`. A passing report includes `EXT-ZOOM-001` in `evidence_items`.

For full AI staging evidence, pair `tools/stagingprobe -probe-ai` with `tools/aiprobe`. The dedicated AI probe validates captured artifacts for provider/model configuration, authenticated generation, timeout/degradation behavior, citation verification, and persisted `ai_request_logs`/`citation_trails`:

```bash
rtk go run ./tools/aiprobe \
  -provider-artifact-url=https://artifacts.staging.example/ai/provider-config.txt \
  -generation-artifact-url=https://artifacts.staging.example/ai/generation.txt \
  -degradation-artifact-url=https://artifacts.staging.example/ai/degradation.txt \
  -citation-artifact-url=https://artifacts.staging.example/ai/citation-verification.txt \
  -audit-artifact-url=https://artifacts.staging.example/ai/audit-persistence.txt
```

The generation artifact must show the canonical route was called with authenticated tenant context and returned cited `generated_curriculum`. The degradation artifact must include timeout, retry, `503`, and `AI_ORCHESTRATION_ENGINE_FAULT` markers. The audit artifact must prove `ai_request_logs` and `citation_trails` persistence with request, organization, user, success/failure, and verification markers. Provider and generation artifacts must be redacted; the probe rejects obvious API key or bearer-token leaks. A passing report includes `EXT-AI-001` in `evidence_items`.

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
  --item-id DEPLOY-TF-001 \
  --artifact artifacts/terraform-plan.txt \
  --command "terraform plan -var-file=terraform.tfvars" \
  --summary "remote backend initialized and staging plan artifact captured"
```

Use this mode for human-reviewed release artifacts such as Terraform plan/apply logs (`DEPLOY-TF-001`), Kubernetes rollout output (`DEPLOY-K8S-001`), Secrets Store CSI/IRSA proof (`SEC-SECRETS-001`), scoped database user proof (`SEC-DBUSER-001`), observability dashboard/alert/retention proof (`OBS-OTEL-001`, `OBS-ALERT-001`), native mobile proof (`CLIENT-MOBILE-001`), rollback drills (`DR-ROLLBACK-001`), backup/restore drills (`DR-BACKUP-001`), and owner/security signoff (`SEC-SIGNOFF-001`). The command marks only the named item as `passed`; blocked, failed, and accepted-risk decisions must still be written with owner/blocker or decision references so the validator can enforce them.

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
  --decision-ref "security/dependency_risk_register.md#DRR-001"
```

The validator requires `blocked` and `failed` entries to include `owner` and `blocker`, and `accepted_risk` entries to include `decision_ref`.

For staged infrastructure, copy `build/terraform/backend.hcl.example` to an uncommitted backend config and run:

```bash
rtk terraform init -backend-config=backend.hcl
rtk terraform plan -var-file=terraform.tfvars
```

After capturing staging Terraform and Kubernetes artifacts, run the deployment probe so the evidence can be recorded into the manifest. Terraform mode requires remote S3 backend init output, a staging plan containing EKS, node group, RDS, Redis, Kubernetes deployments, ingresses, SecretProviderClass manifest, and IAM role resources, plus either Terraform apply output or a deployment approval artifact:

```bash
rtk go run ./tools/deploymentprobe \
  -probe-terraform \
  -terraform-init-url=https://artifacts.staging.example/deploy/terraform-init.txt \
  -terraform-plan-url=https://artifacts.staging.example/deploy/terraform-plan.txt \
  -terraform-apply-url=https://artifacts.staging.example/deploy/terraform-apply-or-approval.txt
```

Kubernetes mode requires rollout status and workload resource artifacts proving API, web, and Rust deployments are rolled out, ready, and available, plus service, ingress, HPA target, and PDB min-availability resources:

```bash
rtk go run ./tools/deploymentprobe \
  -probe-kubernetes \
  -k8s-rollout-url=https://artifacts.staging.example/deploy/kubectl-rollout-status.txt \
  -k8s-resources-url=https://artifacts.staging.example/deploy/kubectl-resources.txt
```

Passing reports include `DEPLOY-TF-001`, `DEPLOY-K8S-001`, or both in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`. This validates captured deployment artifacts; it does not replace `tools/stagingprobe` TLS/readiness checks against the deployed API and web hostnames.

The Terraform skeleton requires an ACM certificate ARN for public ALB ingresses:

```hcl
ingress_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000"
ingress_ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
```

Both API and web ingresses redirect HTTP to HTTPS and attach the configured certificate and SSL policy. Production readiness still requires DNS validation, ACM issuance, staging `plan`/`apply`, and TLS probe evidence against the deployed hostnames.

The Go API exposes `/live` for process liveness and `/ready` for dependency readiness. Terraform maps API liveness/readiness probes to those endpoints and maps the public API ALB health check to `/ready`. The Rust scripture engine binds to `0.0.0.0:50051` by default for pod-to-pod gRPC reachability, can be overridden with `RUST_ENGINE_BIND_ADDRESS`, and serves the standard gRPC health checking service required by Kubernetes gRPC probes on port `50051`.

For deployed Rust engine evidence, run the gRPC and metrics probe from a network location that can reach the Rust service:

```bash
rtk go run ./tools/rustprobe \
  -grpc-address=scriptureforge-rust-engine:50051 \
  -metrics-url=http://scriptureforge-rust-engine:9102/metrics \
  -timeout=5s
```

The report includes `RUST-GRPC-001` in `evidence_items`, verifies the standard gRPC health service reports `SERVING`, and optionally verifies the metrics endpoint exposes ScriptureForge Rust metric names. Attach the resulting JSON with `tools/record-staging-evidence.mjs`.

For deployed tenant isolation evidence through the public API, run the tenant probe with two staging bearer tokens: one token that owns the created journal entry and a second token from another user or tenant that must not be able to read it.

```bash
rtk go run ./tools/tenantprobe \
  -api-base=https://api.staging.example \
  -owner-token="$TENANT_PROBE_OWNER_TOKEN" \
  -blocked-token="$TENANT_PROBE_BLOCKED_TOKEN" \
  -timeout=5s
```

The probe creates an encrypted journal payload, proves the owner token can read it, proves the blocked token receives `404` for the direct read, and proves the blocked token's journal list does not include the created ID. The report includes `DATA-RLS-001` in `evidence_items` so it can be attached with `tools/record-staging-evidence.mjs`.

For deployed mobile readiness evidence, run the mobile probe against captured EAS/native-device artifacts. This is separate from `tools/verify-journal-crypto.mjs`: the local verifier proves the implementation shape under Node/WebCrypto, while `tools/mobileprobe` requires native/EAS proof that the `react-native-quick-crypto` AES-GCM path works outside test shims and that mobile API/WS config points at staging:

```bash
rtk go run ./tools/mobileprobe \
  -eas-artifact-url=https://artifacts.staging.example/mobile/eas-build.txt \
  -native-crypto-smoke-url=https://artifacts.staging.example/mobile/native-crypto-smoke.txt \
  -staging-config-proof-url=https://artifacts.staging.example/mobile/staging-config.txt
```

The native crypto artifact must include `react-native-quick-crypto`, `AES-GCM`, round-trip success, tamper rejection, non-extractable key proof, key disposal proof, and disposed-handle rejection markers. It must not be produced by Node/WebCrypto shims, Expo Crypto placeholders, mocks, or placeholder crypto. The config proof must include HTTPS and WSS staging endpoints and must not use localhost or the old hardcoded `wss://api.scriptureforge.com` value. Passing reports include `CLIENT-MOBILE-001` in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`.

For deployed secret and database principal evidence, run the security probe with redacted staging artifacts and the staged app `DATABASE_URL`. The secret-sync mode expects artifacts for the IRSA service account, `SecretProviderClass`, synced secret metadata, and workload IAM policy. It rejects obvious plaintext DSNs, API keys, private keys, and secret values in metadata artifacts:

```bash
rtk go run ./tools/securityprobe \
  -probe-secrets \
  -service-account-url=https://artifacts.staging.example/k8s/serviceaccount-api.yaml \
  -secret-provider-url=https://artifacts.staging.example/k8s/secret-provider-class.yaml \
  -synced-secret-url=https://artifacts.staging.example/k8s/runtime-secret-redacted.yaml \
  -iam-policy-url=https://artifacts.staging.example/aws/app-secrets-policy.json \
  -access-test-url=https://artifacts.staging.example/aws/app-secrets-access-test.txt
```

The access-test artifact must prove the workload role can read configured ScriptureForge secret ARNs and receives `AccessDenied` for an unscoped secret. This is separate from policy-shape review so `SEC-SECRETS-001` includes observed allow/deny behavior.

The scoped database user mode connects with `STAGING_DATABASE_URL`, does not emit the URL, rejects root/admin/reserved principals, and verifies the connected role is not superuser, `CREATEROLE`, or `CREATEDB`:

```bash
STAGING_DATABASE_URL="$DATABASE_URL" \
  rtk go run ./tools/securityprobe -probe-db-user
```

Passing reports include `SEC-SECRETS-001`, `SEC-DBUSER-001`, or both in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`. This proves the observed staging artifacts and database principal; it still needs clean CI secret scanning and owner review of cloud-side access roles.

For deployed abuse/rate-limit evidence, run the abuse probe against staging with a valid bearer token. The probe repeats auth, AI, journal, rooms, and room-stream requests until each profile returns `429` with `Retry-After` and `X-RateLimit-Limit` headers:

```bash
rtk go run ./tools/abuseprobe \
  -api-base=https://api.staging.example \
  -bearer-token="$STAGING_ABUSE_BEARER_TOKEN" \
  -origin=https://app.staging.example \
  -attempts=35
```

Set staging `ABUSE_LIMIT_*_REQUESTS` values low enough for the run window, or raise `-attempts` above the deployed limits. A passing report includes `ABUSE-LIMIT-001` in `evidence_items`. The probe uses HTTPS only and does not weaken TLS validation for staging.

For deployed rollback and backup/restore evidence, run the resilience probe against captured staging artifacts and readiness/smoke endpoints. Rollback mode requires API readiness before rollback, rollout undo/status output, API readiness after rollback, and AI/Zoom degradation drill evidence:

```bash
rtk go run ./tools/resilienceprobe \
  -probe-rollback \
  -api-ready-before-url=https://artifacts.staging.example/rollback/api-ready-before.json \
  -rollout-artifact-url=https://artifacts.staging.example/rollback/kubectl-rollout-undo.txt \
  -api-ready-after-url=https://artifacts.staging.example/rollback/api-ready-after.json \
  -degradation-drill-url=https://artifacts.staging.example/rollback/degradation-drill.txt
```

Backup mode requires backup/snapshot creation evidence, restore drill evidence, and an application smoke or readiness proof against the restored database:

```bash
rtk go run ./tools/resilienceprobe \
  -probe-backup \
  -backup-artifact-url=https://artifacts.staging.example/backup/snapshot.txt \
  -restore-artifact-url=https://artifacts.staging.example/backup/restore.txt \
  -restored-smoke-url=https://artifacts.staging.example/backup/restored-db-smoke.json
```

Passing reports include `DR-ROLLBACK-001`, `DR-BACKUP-001`, or both in `evidence_items` so they can be attached with `tools/record-staging-evidence.mjs`. This validates captured drill evidence; it does not perform the destructive rollback or restore action by itself.

For deployed observability evidence, run the observability probe against staging telemetry surfaces. The OTEL mode requires collector config proof, API and Rust metrics, a trace backend query, a log backend query, and the same trace ID in both backend query results:

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

Alert/dashboard mode requires deployed dashboard, alert rule, alert delivery/status, and retention proof endpoints or exported artifacts served through URLs:

```bash
rtk go run ./tools/observabilityprobe \
  -probe-alerts \
  -dashboard-url=https://grafana.staging.example/d/scriptureforge-overview \
  -alert-rules-url=https://prometheus.staging.example/api/v1/rules \
  -alertmanager-url=https://alertmanager.staging.example/api/v2/status \
  -retention-url=https://observability.staging.example/retention-proof
```

The report includes `OBS-OTEL-001`, `OBS-ALERT-001`, or both in `evidence_items` only for the requested passing modes. This is still proof collection, not a substitute for importing dashboards, firing a test alert, and confirming the staging telemetry backend retains traces, logs, and metrics.

## Performance Harness

`tools/loadtest` is a small HTTP load harness for repeatable local and staging evidence. The CI smoke path uses an in-process `/health` endpoint so the executable and threshold reporting stay covered without requiring deployed services:

```bash
rtk go run ./tools/loadtest -self-test -duration=2s -concurrency=8 -min-rps=100 -max-p99=200ms
```

For staging readiness, run the same harness against the deployed API health endpoint and raise thresholds to match the architecture target:

```bash
rtk go run ./tools/loadtest -target=https://api.example.com/health -duration=5m -concurrency=512 -min-rps=5000 -max-p99=200ms
```

The command emits JSON with request count, failures, RPS, P50/P95/P99, and threshold status. A passing local self-test does not prove the production 5,000 req/s target; that requires a staging run against real ingress, API, network, and dependency infrastructure. The staging evidence recorder refuses `PERF-HTTP-001` unless the report targets HTTPS, is not local/self-test, sets `min_rps` to at least `5000`, sets `max_p99_ms` to at most `200`, and the observed `rps`/`p99_ms` meet those same thresholds.

External HTTP load reports include `PERF-HTTP-001` in `evidence_items`, so a passing staging report can be attached with `tools/record-staging-evidence.mjs`.

For local WebSocket room-stream coverage, the harness can start an in-process `SocketConnection`, validate room membership through the production handler path, send sequenced room events, and measure accepted-broadcast latency:

```bash
rtk go run ./tools/loadtest -websocket-self-test -concurrency=8 -ws-events-per-client=5 -min-rps=20 -max-p99=200ms
```

This proves the local socket lifecycle and broadcast harness, not multi-instance production fan-out. Final readiness still requires a staging WebSocket load run against real API replicas and Redis.

For staging WebSocket evidence against a deployed room stream, run the harness against a real `wss://` endpoint with a room member token and allowed browser origin:

```bash
rtk go run ./tools/loadtest \
  -websocket \
  -target=wss://api.example.com/api/v1/rooms/stream/room-id \
  -ws-room-id=room-id \
  -ws-token="$ACCESS_TOKEN" \
  -ws-origin=https://app.example.com \
  -concurrency=128 \
  -ws-events-per-client=20 \
  -min-rps=500 \
  -max-p99=200ms
```

The staging WebSocket command uses the same JSON report shape as HTTP load tests and verifies accepted event broadcasts over real upgrade/origin/auth behavior. A production readiness claim still needs the run output captured against real API replicas and Redis.

External WebSocket load reports include `PERF-WS-001` and `DATA-REDIS-001` in `evidence_items`, so passing staging reports can be attached to the evidence manifest with the same recorder. Local `-self-test` and `-websocket-self-test` reports intentionally omit `evidence_items` so they cannot be mistaken for staging proof. The recorder also requires `PERF-WS-001` reports to target WSS, avoid local/self-test targets, set `min_rps` to at least `500`, set `max_p99_ms` to at most `200`, and include observed results meeting those thresholds; `DATA-REDIS-001` cannot be recorded from load evidence unless paired with `PERF-WS-001`.
