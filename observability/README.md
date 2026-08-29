# ScriptureForgeAI Observability Runbook

Status last updated: 2026-06-28

This directory contains the production observability artifacts that match the current local telemetry surface:

- `grafana-scriptureforge-overview.json`: Grafana dashboard for request rate, 5xx rate, route P99 latency, dependency failures, Rust gRPC activity, and trace-correlated JSON logs.
- `prometheus-alerts.yaml`: Prometheus-compatible alert rules for API error rate, traffic absence, auth failures, dependency failures, journal write failures, live room stream failures, and Rust gRPC failures.
- `tools/validate-observability.mjs`: repository validator for dashboard JSON, alert rule coverage, and required metric names.

## Current Application Signals

The current services expose:

- `X-Trace-ID` and W3C `Traceparent` propagation on all observed HTTP responses. Inbound `Traceparent` and `X-Trace-ID` values are accepted only when they contain a 32-character non-zero hex trace ID; otherwise the API emits a generated W3C-shaped trace ID and a nonzero response span ID.
- OpenTelemetry request spans and low-cardinality dependency spans through an env-driven OTLP/HTTP trace exporter when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured.
- Rust gRPC JSON startup/request/error logs with `trace_id` extracted from W3C `traceparent` metadata and service/version/environment fields from deployment env.
- Structured JSON access logs with canonical `timestamp` and `severity` fields plus `trace_id`, `component`, `service`, `service_version`, `deployment_environment`, verified `tenant_id`/`user_id`/`role` when JWT claims are present, `method`, normalized `path`, `status`, `duration_ms`, `remote_addr`, and legacy-compatible `at`/`level` aliases.
- Prometheus text metrics at `/metrics` for `GET` requests on both the Go API and Rust engine. The Go API endpoint requires `Authorization: Bearer <METRICS_AUTH_TOKEN>` outside explicit local/development/test modes and returns `503` if its non-local token is missing; the Rust listener remains a separate metrics target. `HEAD` returns the same headers without a body for lightweight availability checks, and other methods return `405 Method Not Allowed` with `Allow: GET, HEAD`.
  - `scriptureforge_http_requests_total{method,path,status}`
  - `scriptureforge_http_request_duration_seconds_bucket{method,path,status,le}`
  - `scriptureforge_http_request_duration_seconds_sum{method,path,status}`
  - `scriptureforge_http_request_duration_seconds_count{method,path,status}`
  - `scriptureforge_dependency_operations_total{dependency,operation,status}`
  - `scriptureforge_dependency_operation_duration_seconds_sum{dependency,operation,status}`
  - `websocket_active_connections_count`
  - `ai_inference_duration_seconds_sum{profile,status}`
  - `ai_inference_duration_seconds_count{profile,status}`
  - `scriptureforge_rust_engine_embedding_requests_total`
  - `scriptureforge_rust_engine_embedding_failures_total`
  - `scriptureforge_rust_engine_vector_search_requests_total`
  - `scriptureforge_rust_engine_vector_search_failures_total`

The Go middleware intentionally excludes `/metrics` scrapes from access logs and application request counters so Prometheus polling does not distort traffic, latency, or absent-traffic alerts.

The dependency metrics are local app-level counters for low-cardinality dependency operations. The Go API currently emits them for abuse limiter decisions by route profile, auth/session Postgres register/login/refresh/logout/MFA operations, journal Postgres create/list/read operations, room Postgres membership/list/create operations, Redis room state/append operations including the WebSocket event persistence path, WebSocket room broadcast success/drop outcomes, AI provider chat completion outcomes such as timeout/network errors, verification failures, and successful citation-verified responses, Rust engine vector-search outcomes, and Zoom meeting create/status/terminate outcomes including circuit-open and offline fallback paths, plus bounded active-room status reconciliation outcomes. Each `ObserveDependencyFromContext` call also emits a low-cardinality child span named `dependency.<dependency>.<operation>` with `scriptureforge.dependency`, `scriptureforge.dependency.operation`, `scriptureforge.dependency.status`, and `scriptureforge.dependency.duration_ms` attributes; statuses containing `error`, `fail`, `fault`, `timeout`, `mock`, `denied`, `dropped`, `invalid`, `expired`, `limited`, `rejected`, or `unavailable` mark the span with OpenTelemetry error status. The architecture-facing metric profiles also include `websocket_active_connections_count` for accepted live-room streams and `ai_inference_duration_seconds` summary series by model/profile and outcome status. They support staging dashboards and failure alerts, but they do not replace deployed collector validation or provider-native telemetry. Staging still needs deployed collector validation for these dependency spans across Redis, Postgres, Zoom, AI provider calls, WebSocket fan-out, and Rust gRPC span export.

## OpenTelemetry Configuration

The Go API keeps OpenTelemetry disabled unless a collector endpoint is configured. Production and staging should set:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP/HTTP collector endpoint, for example `http://otel-collector.observability:4318` or `otel-collector.observability:4318`.
- `OTEL_EXPORTER_OTLP_INSECURE`: `true` only for in-cluster plaintext collector traffic.
- `OTEL_SERVICE_NAME`: defaults to `scriptureforge-api`.
- `SERVICE_VERSION`: release/version identifier attached to spans.
- `DEPLOYMENT_ENVIRONMENT`: staging, production, or equivalent environment label.
- `OTEL_SDK_DISABLED`: set to `true` only to force-disable tracing.

## Deployment Wiring

1. Scrape the Go API `/metrics` endpoint from the Kubernetes service or pod with the API-only `METRICS_AUTH_TOKEN` bearer credential. Configure Prometheus or the staging evidence probe with the same secret without placing it in URLs or report bodies.
2. Scrape the Rust engine `/metrics` endpoint on port `9102` from the Kubernetes service or pod.
3. Ship JSON stdout logs to the staging log backend and preserve `trace_id`, `component`, `service_version`, `deployment_environment`, and verified tenant principal fields.
4. Set `OTEL_EXPORTER_OTLP_ENDPOINT` on the Go API deployment and verify spans arrive at the staging collector/backend.
5. Import `grafana-scriptureforge-overview.json` into Grafana with `PROMETHEUS_DS_UID` and `LOKI_DS_UID` mapped to the staging data sources.
6. Load `prometheus-alerts.yaml` into the staging Prometheus or alert-manager compatible ruleset.
7. Configure retention:
   - Metrics: at least 30 days for staging, 90 days for production.
   - Logs: at least 14 days for staging, 30 days for production.
   - Traces: at least 7 days for staging, 14 days for production.
8. Run a staging smoke that creates traceable requests across auth, journal, room polling, room stream handshake, Rust gRPC embedding/search, AI fail-closed behavior, and Zoom webhook verification.
9. Capture `tools/observabilityprobe` evidence from non-local, non-private public telemetry/artifact URLs for collector, API metrics, trace query, log query, dashboard, alert, and retention proofs. Supply `STAGING_METRICS_AUTH_TOKEN` or `-metrics-auth-token` for the protected API metrics scrape. The Rust metrics URL may remain an in-cluster service URL when the probe is run from inside the staging network.

## Incident Triage

When an alert fires:

1. Use the Grafana dashboard to identify the affected route, status class, and P99 latency bucket.
2. Copy a recent `trace_id` from logs for the failing route.
3. Follow that trace through the log backend and tracing backend.
4. Check the dependency named by the route:
   - Auth: JWT secret, refresh-token table, MFA state, abuse limiter profile metrics.
   - Journal: Postgres RLS context, no-plaintext validation, encrypted payload shape.
   - Rooms/WebSocket: allowed origins, JWT claims, room membership, Redis state manager.
   - AI: provider key readiness, timeout/retry configuration, citation verification, audit persistence.
   - Zoom: signature validation, circuit breaker state, meeting-to-room mapping.
5. Check `scriptureforge_dependency_operations_total` and `scriptureforge_dependency_operation_duration_seconds_sum` by `dependency`, `operation`, and `status`, plus `websocket_active_connections_count`, `dependency="websocket",operation="room_broadcast",status="dropped"`, and `ai_inference_duration_seconds` for room stream, fan-out pressure, and model/profile behavior, before drilling into provider-specific logs.
   `OBS-OTEL-001` staging evidence specifically requires successful `dependency="rust_engine",operation="vector_search"` count/duration markers plus `websocket_active_connections_count`, WebSocket room broadcast drop metrics, and `ai_inference_duration_seconds_*` profile markers from the Go API `/metrics` surface after staging flows exercise Rust, live-room, and AI paths.
6. Record the alert, trace ID, root cause, and rollback/degradation action in the release evidence bundle.

## Remaining Production Closure

These files are local/staging configuration artifacts. They do not by themselves prove the architecture's OpenTelemetry requirement. Production readiness still requires:

- Deployed OTLP collector/backend proof for Go API traces and dependency spans across Rust gRPC, Postgres, Redis, Zoom, and AI provider calls. The Terraform skeleton exposes `otel_exporter_otlp_endpoint`, `otel_exporter_otlp_insecure`, and `service_version`, but no collector has been applied or validated from this repo.
- Rust gRPC log shipping proof showing `scriptureforge-rust-engine` events with propagated `trace_id`, `SERVICE_VERSION`, and `DEPLOYMENT_ENVIRONMENT` fields.
- Real staging dashboard screenshots or exported snapshots after traffic.
- Alert delivery proof to the production paging/ticketing destination.
- Retention proof from the selected telemetry backend.
