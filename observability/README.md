# ScriptureForgeAI Observability Runbook

Status last updated: 2026-06-25

This directory contains the production observability artifacts that match the current local telemetry surface:

- `grafana-scriptureforge-overview.json`: Grafana dashboard for request rate, 5xx rate, route latency, route status mix, Rust gRPC activity, and trace-correlated JSON logs.
- `prometheus-alerts.yaml`: Prometheus-compatible alert rules for API error rate, traffic absence, auth failures, journal write failures, live room stream failures, and Rust gRPC failures.
- `tools/validate-observability.mjs`: repository validator for dashboard JSON, alert rule coverage, and required metric names.

## Current Application Signals

The current services expose:

- `X-Trace-ID` and W3C `Traceparent` propagation on all observed HTTP responses.
- OpenTelemetry request spans through an env-driven OTLP/HTTP trace exporter when `OTEL_EXPORTER_OTLP_ENDPOINT` is configured.
- Rust gRPC JSON startup/request/error logs with `trace_id` extracted from W3C `traceparent` metadata and service/version/environment fields from deployment env.
- Structured JSON access logs with `trace_id`, `method`, normalized `path`, `status`, `duration_ms`, `remote_addr`, and timestamp fields.
- Prometheus text metrics at `/metrics`:
  - `scriptureforge_http_requests_total{method,path,status}`
  - `scriptureforge_http_request_duration_seconds_sum{method,path,status}`
  - `scriptureforge_rust_engine_embedding_requests_total`
  - `scriptureforge_rust_engine_embedding_failures_total`
  - `scriptureforge_rust_engine_vector_search_requests_total`
  - `scriptureforge_rust_engine_vector_search_failures_total`

The current metrics, API request spans, and Rust gRPC correlated logs are enough for baseline request/error/latency dashboards and trace propagation checks. They are not enough for full production observability across every dependency. Staging still needs deployed collector validation and dependency-specific metrics/spans for Redis, Postgres, Zoom, AI provider calls, WebSocket fan-out, and Rust gRPC span export.

## OpenTelemetry Configuration

The Go API keeps OpenTelemetry disabled unless a collector endpoint is configured. Production and staging should set:

- `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP/HTTP collector endpoint, for example `http://otel-collector.observability:4318` or `otel-collector.observability:4318`.
- `OTEL_EXPORTER_OTLP_INSECURE`: `true` only for in-cluster plaintext collector traffic.
- `OTEL_SERVICE_NAME`: defaults to `scriptureforge-api`.
- `SERVICE_VERSION`: release/version identifier attached to spans.
- `DEPLOYMENT_ENVIRONMENT`: staging, production, or equivalent environment label.
- `OTEL_SDK_DISABLED`: set to `true` only to force-disable tracing.

## Deployment Wiring

1. Scrape the Go API `/metrics` endpoint from the Kubernetes service or pod.
2. Scrape the Rust engine `/metrics` endpoint on port `9102` from the Kubernetes service or pod.
3. Ship JSON stdout logs to the staging log backend and preserve `trace_id`.
4. Set `OTEL_EXPORTER_OTLP_ENDPOINT` on the Go API deployment and verify spans arrive at the staging collector/backend.
5. Import `grafana-scriptureforge-overview.json` into Grafana with `PROMETHEUS_DS_UID` and `LOKI_DS_UID` mapped to the staging data sources.
6. Load `prometheus-alerts.yaml` into the staging Prometheus or alert-manager compatible ruleset.
7. Configure retention:
   - Metrics: at least 30 days for staging, 90 days for production.
   - Logs: at least 14 days for staging, 30 days for production.
   - Traces: at least 7 days for staging, 14 days for production.
8. Run a staging smoke that creates traceable requests across auth, journal, room polling, room stream handshake, Rust gRPC embedding/search, AI fail-closed behavior, and Zoom webhook verification.

## Incident Triage

When an alert fires:

1. Use the Grafana dashboard to identify the affected route and status class.
2. Copy a recent `trace_id` from logs for the failing route.
3. Follow that trace through the log backend and tracing backend.
4. Check the dependency named by the route:
   - Auth: JWT secret, refresh-token table, MFA state, abuse limiter.
   - Journal: Postgres RLS context, no-plaintext validation, encrypted payload shape.
   - Rooms/WebSocket: allowed origins, JWT claims, room membership, Redis state manager.
   - AI: provider key readiness, timeout/retry configuration, citation verification, audit persistence.
   - Zoom: signature validation, circuit breaker state, meeting-to-room mapping.
5. Record the alert, trace ID, root cause, and rollback/degradation action in the release evidence bundle.

## Remaining Production Closure

These files are local/staging configuration artifacts. They do not by themselves prove the architecture's OpenTelemetry requirement. Production readiness still requires:

- Deployed OTLP collector/backend proof for Go API traces and follow-on spans across Rust gRPC, Postgres, Redis, Zoom, and AI provider calls. The Terraform skeleton exposes `otel_exporter_otlp_endpoint`, `otel_exporter_otlp_insecure`, and `service_version`, but no collector has been applied or validated from this repo.
- Rust gRPC log shipping proof showing `scriptureforge-rust-engine` events with propagated `trace_id`, `SERVICE_VERSION`, and `DEPLOYMENT_ENVIRONMENT` fields.
- Real staging dashboard screenshots or exported snapshots after traffic.
- Alert delivery proof to the production paging/ticketing destination.
- Retention proof from the selected telemetry backend.
