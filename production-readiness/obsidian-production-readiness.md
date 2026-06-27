# scriptureforge-production-readiness

---
title: ScriptureForgeAI Production Readiness
type: dashboard
status: active
owner: "team"
updated: 2026-06-27
tags:
  - production-readiness
  - serena
  - obsidian
  - scriptureforge
---

## Commanding View

- Core execution plan: [[SF-roadmap|SF-roadmap.md]]
- Stability boundary/assumptions: [[SF-architecture|SF-architecture.md]]
- Audit authority: [[FUNCTIONALITY_AUDIT_BRIEFING|FUNCTIONALITY_AUDIT_BRIEFING.md]]

## Obsidian-Trackable Production Gaps

```dataview
TASK
FROM "production-readiness"
WHERE contains(file.name, "obsidian-production-readiness")
```

Use this note as a lightweight tracker for unresolved external blockers and local proof gaps before declaring production-ready status.

Serena setup source: [[serena-setup|production-readiness/serena-setup.md]]

- [ ] **F-AUD External Evidence Closure**: close `production-readiness/staging-evidence.staging.json` blockers with deployed artifacts.
- [ ] **CI Release Evidence Upload**: run CI on the exact release `git_head` and ingest `ci-release-evidence` into manifest.
- [ ] **Terraform Live Validation**: capture real `plan/apply` + TLS/ingress/secret/IRSA proofs against staging.
- [ ] **Staging AI Validation**: run real provider/degradation/citation smoke and persist `EXT-AI-001`.
- [ ] **Staging Zoom Validation**: run real webhook and fallback path captures for `EXT-ZOOM-001`.
- [ ] **Web/Mobile Staging Smoke**: verify login/journal/room/WebSocket flows against staging endpoints.
- [x] **Network-Locked Local Gates**: local reproducibility is maintained by gating `npm audit` and `terraform init` in `run-local-gates` through network-aware wrappers that fail closed only on non-network errors.
- [x] **Roadmap/Architecture Drift Control**: keep `SF-roadmap.md` and `SF-architecture.md` aligned with implemented routes, tenancy boundaries, and production gates.
- [x] **Obsidian/Serena Drift Gate**: `SF-architecture.md` and `SF-roadmap.md` now include production-aligned stack versions and full `/api/v1` route coverage.
- [x] **Serena/Obsidian Pre-Merge Gate**: ensure every new implementation file and route change is mirrored in both `SF-roadmap.md` and `SF-architecture.md` before merge.

## Serena-Enabled Work Tracking

- Added language indexing targets: `go`, `typescript`, `rust`, `terraform`, `markdown`, `yaml`.
- Added workspace links for Serena cross-package browsing:
  - `web`
  - `mobile`
  - `services/scripture-engine`
- Use this file as the canonical Obsidian/Serena handoff surface for PR planning and weekly readiness check-ins.

<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-START -->
## Staging Evidence Snapshot (staging)
- release_candidate: e2ed5e6ba59d96891a6deb89c838b15ea2216dd4
- strict_release_ready: no
- counts: passed=0, pending_external=21, blocked=0, failed=0, accepted_risk=0
- expected_release_candidate: not checked
- blocking items:
  - SRC-CI-001 [pending_external]: Clean pushed GitHub Actions run for the exact release branch.
    - required: tools/ciprobe JSON report with SRC-CI-001 evidence item from the uploaded artifact file or URL
    - required: Uploaded GitHub Actions ci-release-evidence artifact from the release SHA
    - required: GitHub Actions run URL
    - required: Commit SHA
    - required: All required workflow jobs passing
  - DEPLOY-TF-001 [pending_external]: Terraform remote state is initialized and the staging plan/apply completes against real inputs.
    - required: tools/deploymentprobe -probe-terraform JSON report with DEPLOY-TF-001 evidence item
    - required: terraform init output with remote backend
    - required: terraform plan artifact proving EKS, node group, RDS, Redis, workload deployments, ingresses, SecretProviderClass, and IAM role resources
    - required: terraform apply output or DEPLOY-TF-001 deployment approval record
  - DEPLOY-TLS-001 [pending_external]: DNS, ACM, ALB ingress, HTTPS redirect, and TLS policy are proven against deployed API and web hostnames.
    - required: tools/stagingprobe JSON report
    - required: HTTPS DNS lookup artifact for deployed API and web hostnames
    - required: HTTPS ACM certificate status and TLS policy artifact
    - required: HTTPS probe output
    - required: HTTP to HTTPS redirect probe output
  - DEPLOY-K8S-001 [pending_external]: Kubernetes API, web, and Rust engine workloads are running with readiness/liveness probes, PDBs, HPAs, and rolling update settings.
    - required: tools/deploymentprobe -probe-kubernetes JSON report with DEPLOY-K8S-001 evidence item
    - required: kubectl rollout status output proving API, web, and Rust workloads are rolled out, ready, and available
    - required: kubectl get deploy,svc,ingress,hpa,pdb output proving services, ingresses, HPA targets, and PDB min availability
  - SEC-SECRETS-001 [pending_external]: Secrets Store CSI and IRSA sync runtime secrets from the cloud secret manager without committed plaintext.
    - required: tools/securityprobe -probe-secrets JSON report with SEC-SECRETS-001 evidence item
    - required: Secrets Store CSI driver status
    - required: IRSA role annotation and trust policy
    - required: SecretProviderClass sync output
    - required: Scoped Secrets Manager access test proving configured-secret allow and unscoped-secret AccessDenied
  - SEC-DBUSER-001 [pending_external]: DATABASE_URL uses a scoped application database user rather than the RDS root user.
    - required: tools/securityprobe -probe-db-user JSON report with SEC-DBUSER-001 evidence item
    - required: Redacted DATABASE_URL principal proof
    - required: Database grants for app role
    - required: Denied privileged operation probe
  - ABUSE-LIMIT-001 [pending_external]: Auth, AI, journal, room, and WebSocket abuse limits are observed through real staging ingress behavior.
    - required: tools/abuseprobe JSON report with ABUSE-LIMIT-001 evidence item
    - required: 429 responses for auth, AI, journal, rooms, and WebSocket profiles
    - required: Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset header proof
    - required: HTTPS redacted artifact proving staging ABUSE_LIMIT_* configuration used for the probe
  - DATA-RLS-001 [pending_external]: Tenant RLS behavior is proven through the deployed API and staging database connection pool.
    - required: tools/tenantprobe JSON report with DATA-RLS-001 evidence item
    - required: Same-tenant read/write probe output
    - required: Cross-tenant read/write denial output
    - required: Redacted database role, app.current_org_id, forced row_security, tenant table, and cross-tenant write-denial proof
  - DATA-REDIS-001 [pending_external]: Redis-backed room sequencing is contiguous under deployed multi-client concurrency.
    - required: External WebSocket load report with DATA-REDIS-001 evidence item
    - required: HTTPS Redis telemetry artifact from the same run
    - required: Redis sequence ordering assertion output with no duplicate or skipped sequence proof
  - RUST-GRPC-001 [pending_external]: Deployed Rust gRPC service is reachable from the Go API and exposes health and metrics.
    - required: tools/rustprobe JSON report with RUST-GRPC-001 evidence item
    - required: gRPC health probe output
    - required: API to Rust integration probe
    - required: Rust metrics scrape output
  - OBS-OTEL-001 [pending_external]: OpenTelemetry collector/backend receives traces and preserves trace IDs across API and Rust logs.
    - required: tools/observabilityprobe -probe-otel JSON report with OBS-OTEL-001 evidence item
    - required: Collector endpoint configuration with OTLP receivers/exporters/service pipeline
    - required: API metrics scrape output with request count, status labels, and duration sum
    - required: Rust metrics scrape output with request and failure counters
    - required: Trace search output proving the same trace crosses scriptureforge-api and scriptureforge-rust-engine
    - required: Log query output with trace_id, scriptureforge-api, scriptureforge-rust-engine, SERVICE_VERSION, and DEPLOYMENT_ENVIRONMENT
  - OBS-ALERT-001 [pending_external]: Dashboard import, alert delivery, and telemetry retention are proven in staging.
    - required: tools/observabilityprobe -probe-alerts JSON report with OBS-ALERT-001 evidence item
    - required: Grafana dashboard import screenshot or export with API, latency, Rust, and trace_id panels
    - required: Alert rules loaded for high error rate, route latency, and Rust engine failures
    - required: Delivered Alertmanager test alert output
    - required: 30-day trace/log/metric retention policy proof
  - CLIENT-WEB-001 [pending_external]: Deployed web app completes browser smoke flows against staging API and WebSocket endpoints.
    - required: tools/stagingprobe JSON report with CLIENT-WEB-001 evidence item
    - required: HTTPS browser smoke artifact for login/register flow
    - required: HTTPS browser smoke artifact for journal save/load flow
    - required: HTTPS browser smoke artifact for room create/select/WebSocket flow
  - CLIENT-MOBILE-001 [pending_external]: Mobile native-device or EAS validation proves the AES-GCM binding and staging endpoint config outside Node/WebCrypto shims.
    - required: tools/mobileprobe JSON report with CLIENT-MOBILE-001 evidence item
    - required: EAS or native-device run output
    - required: Native crypto smoke output
    - required: Staging API/WS config proof
  - EXT-ZOOM-001 [pending_external]: Zoom OAuth, meeting creation fallback, webhook signature validation, duplicate webhook idempotency, and room mapping are proven with staging credentials.
    - required: tools/zoomprobe JSON report with EXT-ZOOM-001 evidence item
    - required: tools/stagingprobe -probe-zoom JSON report
    - required: Zoom OAuth probe output
    - required: Meeting create or fallback output
    - required: Zoom timeout/circuit-open fallback output
    - required: Webhook delivery/signature proof
    - required: Duplicate webhook idempotency proof
    - required: Meeting-to-room mapping proof
  - EXT-AI-001 [pending_external]: AI provider configuration, timeout/degradation behavior, citation verification, and audit persistence are proven in staging.
    - required: tools/aiprobe JSON report with EXT-AI-001 evidence item
    - required: tools/stagingprobe -probe-ai JSON report
    - required: Provider readiness probe
    - required: Authenticated tenant generation probe
    - required: Timeout/retry/degradation probe
    - required: Citation verification output
    - required: ai_request_logs and citation_trails query output with request_id, organization_id, and user_id proof
  - PERF-HTTP-001 [pending_external]: Staging HTTP load test proves or revises the architecture target of 5000 requests per second with P99 under 200ms.
    - required: tools/loadtest JSON report with PERF-HTTP-001 evidence item
    - required: HTTPS ingress/API replica distribution artifact from the same run
    - required: HTTPS database and Redis telemetry artifact from the same run
  - PERF-WS-001 [pending_external]: Staging WebSocket load test proves multi-instance fan-out and Redis sequencing with real API replicas.
    - required: tools/loadtest -websocket JSON report with PERF-WS-001 and DATA-REDIS-001 evidence items
    - required: HTTPS API replica distribution artifact from the same run
    - required: HTTPS Redis telemetry artifact from the same run
  - DR-ROLLBACK-001 [pending_external]: Rollback and degradation paths are exercised in staging.
    - required: tools/resilienceprobe -probe-rollback JSON report with DR-ROLLBACK-001 evidence item
    - required: kubectl rollout undo or equivalent rollback output naming reverted revision and scriptureforge-api
    - required: API readiness before and after rollback with service_version and deployment_environment
    - required: AI/Zoom degradation drill output proving AI_ORCHESTRATION_ENGINE_FAULT and Zoom offline://in-person fallback
  - DR-BACKUP-001 [pending_external]: RDS backup creation and restore drill are proven in staging.
    - required: tools/resilienceprobe -probe-backup JSON report with DR-BACKUP-001 evidence item
    - required: Backup/snapshot creation output proving available encrypted KMS snapshot and retention
    - required: Restore drill output proving restored endpoint and checksum
    - required: Application smoke against restored database covering tenant and journal behavior
  - SEC-SIGNOFF-001 [pending_external]: Threat model, dependency risk register, and residual production risks receive owner/security signoff.
    - required: Threat model review approval
    - required: DRR-001 accept-or-remediate decision
    - required: Release risk signoff record

<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-END -->
