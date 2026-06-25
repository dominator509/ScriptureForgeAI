import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const dashboardPath = new URL('../observability/grafana-scriptureforge-overview.json', import.meta.url);
const alertsPath = new URL('../observability/prometheus-alerts.yaml', import.meta.url);
const runbookPath = new URL('../observability/README.md', import.meta.url);
const rustEnginePath = new URL('../services/scripture-engine/src/main.rs', import.meta.url);
const terraformAppPath = new URL('../build/terraform/app.tf', import.meta.url);

const requiredMetrics = [
  'scriptureforge_http_requests_total',
  'scriptureforge_http_request_duration_seconds_sum',
];

const requiredDashboardRunbookMetrics = [
  ...requiredMetrics,
  'scriptureforge_rust_engine_embedding_requests_total',
  'scriptureforge_rust_engine_vector_search_requests_total',
];

const requiredAlerts = [
  'ScriptureForgeHighErrorRate',
  'ScriptureForgeTrafficAbsent',
  'ScriptureForgeAuthFailureSpike',
  'ScriptureForgeRouteLatencyElevated',
  'ScriptureForgeJournalWriteFailures',
  'ScriptureForgeRoomStreamFailures',
  'ScriptureForgeRustEngineFailures',
];

const dashboard = JSON.parse(await readFile(dashboardPath, 'utf8'));
const alerts = await readFile(alertsPath, 'utf8');
const runbook = await readFile(runbookPath, 'utf8');
const rustEngine = await readFile(rustEnginePath, 'utf8');
const terraformApp = await readFile(terraformAppPath, 'utf8');

assert.equal(dashboard.uid, 'scriptureforge-overview');
assert.ok(Array.isArray(dashboard.panels), 'dashboard panels must be an array');
assert.ok(dashboard.panels.length >= 5, 'dashboard must include baseline request, error, latency, and log panels');

const serializedDashboard = JSON.stringify(dashboard);
for (const metric of requiredMetrics) {
  assert.ok(serializedDashboard.includes(metric), `dashboard missing ${metric}`);
  assert.ok(alerts.includes(metric), `alerts missing ${metric}`);
  assert.ok(runbook.includes(metric), `runbook missing ${metric}`);
}
for (const metric of requiredDashboardRunbookMetrics) {
  assert.ok(serializedDashboard.includes(metric), `dashboard missing ${metric}`);
  assert.ok(runbook.includes(metric), `runbook missing ${metric}`);
}

for (const alert of requiredAlerts) {
  assert.ok(alerts.includes(`alert: ${alert}`), `missing alert ${alert}`);
}

for (const phrase of ['Traceparent', 'trace_id', 'retention', 'OpenTelemetry', 'staging']) {
  assert.ok(runbook.includes(phrase), `runbook missing ${phrase}`);
}

for (const phrase of [
  'traceparent_from_request',
  'emit_log',
  'observability_config',
  'render_prometheus',
  'run_metrics_server',
  'scriptureforge-rust-engine',
]) {
  assert.ok(rustEngine.includes(phrase), `Rust engine observability missing ${phrase}`);
}

for (const phrase of [
  'value = "scriptureforge-rust-engine"',
  'name  = "RUST_ENGINE_METRICS_ADDRESS"',
  'name  = "SERVICE_VERSION"',
  'name  = "DEPLOYMENT_ENVIRONMENT"',
  'name  = "OTEL_EXPORTER_OTLP_ENDPOINT"',
]) {
  assert.ok(terraformApp.includes(phrase), `Terraform Rust observability env missing ${phrase}`);
}

console.log('observability artifacts validated');
