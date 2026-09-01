import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const observabilityArtifactPaths = {
  dashboard: new URL('../observability/grafana-scriptureforge-overview.json', import.meta.url),
  alerts: new URL('../observability/prometheus-alerts.yaml', import.meta.url),
  runbook: new URL('../observability/README.md', import.meta.url),
  rustEngine: new URL('../services/scripture-engine/src/main.rs', import.meta.url),
  terraformApp: new URL('../build/terraform/app.tf', import.meta.url),
  journalHTTP: new URL('../internal/ports/journal_http.go', import.meta.url),
  authHTTP: new URL('../internal/ports/auth_http.go', import.meta.url),
  roomsHTTP: new URL('../internal/ports/rooms_http.go', import.meta.url),
  roomsWSS: new URL('../internal/ports/driving_wss.go', import.meta.url),
  llmClient: new URL('../internal/adapters/llm/client.go', import.meta.url),
  zoomClient: new URL('../internal/adapters/integration_zoom/zoom_client.go', import.meta.url),
  abuseLimiter: new URL('../internal/domain/abuse/limiter.go', import.meta.url),
  apiObservability: new URL('../internal/domain/observability/observability.go', import.meta.url),
  apiObservabilityTest: new URL('../internal/domain/observability/observability_test.go', import.meta.url),
  platformMain: new URL('../cmd/platform-engine/main.go', import.meta.url),
  metricsSecurity: new URL('../cmd/platform-engine/metrics_security.go', import.meta.url),
  authMiddleware: new URL('../internal/domain/auth/middleware.go', import.meta.url),
  observabilityProbe: new URL('../tools/observabilityprobe/main.go', import.meta.url),
  recordStagingEvidence: new URL('../tools/record-staging-evidence.mjs', import.meta.url),
  validateStagingEvidence: new URL('../tools/validate-staging-evidence.mjs', import.meta.url),
  stagingEvidenceExample: new URL('../production-readiness/staging-evidence.example.json', import.meta.url),
};

export const observabilityProofMarkers = [
  'dashboard_metrics=true',
  'alert_rules=true',
  'trace_id_logs=true',
  'trace_id_shape_guard=true',
  'structured_log_canonical_fields=true',
  'metrics_endpoint=true',
  'metrics_authentication=true',
  'dependency_spans=true',
  'websocket_profile_metrics=true',
  'ai_profile_metrics=true',
  'rust_metrics=true',
  'otel_env_wiring=true',
  'staging_evidence_contract=true',
];

export const requiredMetrics = [
  'scriptureforge_http_requests_total',
  'scriptureforge_http_request_duration_seconds_bucket',
  'scriptureforge_http_request_duration_seconds_sum',
  'scriptureforge_http_request_duration_seconds_count',
  'scriptureforge_dependency_operations_total',
  'scriptureforge_dependency_operation_duration_seconds_sum',
  'websocket_active_connections_count',
  'ai_inference_duration_seconds',
];

export const requiredDashboardMetrics = [
  'scriptureforge_http_requests_total',
  'scriptureforge_http_request_duration_seconds_bucket',
  'scriptureforge_http_request_duration_seconds_sum',
  'scriptureforge_dependency_operations_total',
  'scriptureforge_dependency_operation_duration_seconds_sum',
  'websocket_active_connections_count',
  'ai_inference_duration_seconds',
];

export const requiredAlertMetrics = [
  'scriptureforge_http_requests_total',
  'scriptureforge_http_request_duration_seconds_bucket',
  'scriptureforge_dependency_operations_total',
  'scriptureforge_dependency_operation_duration_seconds_sum',
  'ai_inference_duration_seconds',
];

export const requiredDashboardRunbookMetrics = [
  ...requiredDashboardMetrics,
  'scriptureforge_rust_engine_embedding_requests_total',
  'scriptureforge_rust_engine_vector_search_requests_total',
];

export const requiredAlerts = [
  'ScriptureForgeHighErrorRate',
  'ScriptureForgeTrafficAbsent',
  'ScriptureForgeAuthFailureSpike',
  'ScriptureForgeAbuseLimitSpike',
  'ScriptureForgeRouteLatencyElevated',
  'ScriptureForgeDependencyFailures',
  'ScriptureForgeAIInferenceLatencyElevated',
  'ScriptureForgeJournalWriteFailures',
  'ScriptureForgeRoomStreamFailures',
  'ScriptureForgeRoomBroadcastDrops',
  'ScriptureForgeRustEngineFailures',
];

export async function loadObservabilitySources(paths = observabilityArtifactPaths) {
  const entries = await Promise.all(
    Object.entries(paths).map(async ([name, path]) => [name, await readFile(path, 'utf8')]),
  );
  const sources = Object.fromEntries(entries);
  sources.dashboard = JSON.parse(sources.dashboard);
  sources.stagingEvidenceExample = sources.stagingEvidenceExample.replaceAll('\\"', '"');
  return sources;
}

export function validateObservabilitySources(sources) {
  const {
    dashboard,
    alerts,
    runbook,
    rustEngine,
    terraformApp,
    journalHTTP,
    authHTTP,
    roomsHTTP,
    roomsWSS,
    llmClient,
    zoomClient,
    abuseLimiter,
    apiObservability,
    apiObservabilityTest,
    platformMain,
    metricsSecurity,
    authMiddleware,
    observabilityProbe,
    recordStagingEvidence,
    validateStagingEvidence,
    stagingEvidenceExample,
  } = sources;

assert.equal(dashboard.uid, 'scriptureforge-overview');
assert.ok(Array.isArray(dashboard.panels), 'dashboard panels must be an array');
assert.ok(dashboard.panels.length >= 5, 'dashboard must include baseline request, error, latency, and log panels');

const serializedDashboard = JSON.stringify(dashboard);
for (const metric of requiredMetrics) {
  assert.ok(runbook.includes(metric), `runbook missing ${metric}`);
}
for (const metric of requiredDashboardMetrics) {
  assert.ok(serializedDashboard.includes(metric), `dashboard missing ${metric}`);
}
for (const metric of requiredAlertMetrics) {
  assert.ok(alerts.includes(metric), `alerts missing ${metric}`);
}
for (const metric of requiredDashboardRunbookMetrics) {
  assert.ok(serializedDashboard.includes(metric), `dashboard missing ${metric}`);
  assert.ok(runbook.includes(metric), `runbook missing ${metric}`);
}

for (const alert of requiredAlerts) {
  assert.ok(alerts.includes(`alert: ${alert}`), `missing alert ${alert}`);
}

for (const phrase of [
  'histogram_quantile(0.99',
  'scriptureforge_http_request_duration_seconds_bucket',
  'Route P99 Latency',
]) {
  assert.ok(serializedDashboard.includes(phrase) || alerts.includes(phrase), `missing P99 latency observability phrase ${phrase}`);
}

for (const phrase of ['Traceparent', 'trace_id', 'retention', 'OpenTelemetry', 'staging']) {
  assert.ok(runbook.includes(phrase), `runbook missing ${phrase}`);
}

for (const phrase of [
  'Component',
  'Severity              string `json:"severity"`',
  'Timestamp             string `json:"timestamp"`',
  'ServiceVersion',
  'DeploymentEnvironment',
  'TenantID',
  'UserID',
  'EnrichRequestLogFields',
  'contextKeyRequestLogFields',
  'isMetricsScrape',
  'path == "/metrics"',
  'websocketActive',
  'aiInferenceCount',
  'ObserveAIInferenceFromContext',
  'ObserveWebSocketActiveConnectionFromContext',
  'recordDependencySpan',
  'dependencyStatusIsError',
  'strings.Contains(status, "dropped")',
  'strings.Contains(status, "rejected")',
  'strings.Contains(status, "unavailable")',
  'scriptureforge.dependency.duration_ms',
  'normalizeTraceID',
  'ensureTraceID',
  'fallbackTraceID',
  'contextWithTraceID',
  'TraceIDFromHex',
  'wroteHeader',
  'Flush()',
  'Unwrap()',
  '0000000000000001',
  'ai_inference_duration_seconds',
  'websocket_active_connections_count',
]) {
  assert.ok(apiObservability.includes(phrase), `API structured log observability missing ${phrase}`);
}

for (const phrase of [
  'protectedMetricsHandler(observer.MetricsHandler())',
]) {
  assert.ok(platformMain.includes(phrase), `API metrics authentication missing ${phrase}`);
}
for (const phrase of ['METRICS_AUTH_TOKEN', 'ConstantTimeCompare', 'StatusServiceUnavailable']) {
  assert.ok(metricsSecurity.includes(phrase), `API metrics authentication missing ${phrase}`);
}

for (const phrase of [
  'TestMiddlewareRejectsInvalidXTraceIDAndGeneratorFallbacks',
  'access log missing canonical timestamp field',
  'access log missing canonical severity field',
  'TestMiddlewareBindsOTelSpanToAcceptedXTraceID',
  'TestMiddlewarePreservesStreamingResponseWriterCapabilities',
  'exported span trace id',
  'implicit 200 committed by flush',
  'client-trace-789',
  'not-a-valid-trace-id',
  '0000000000000001',
  'aaaabbbbccccddddeeeeffff00001111',
]) {
  assert.ok(apiObservabilityTest.includes(phrase), `API trace ID shape guard test missing ${phrase}`);
}

for (const phrase of [
  'EnrichRequestLogFields',
  'claims.OrganizationID',
  'claims.UserID',
  'claims.Role',
]) {
  assert.ok(authMiddleware.includes(phrase), `Auth middleware structured log enrichment missing ${phrase}`);
}

for (const phrase of [
  'traceparent_from_request',
  'emit_log',
  'observability_config',
  'render_prometheus',
  'metrics_response_for_request',
  '"HEAD"',
  '"405 Method Not Allowed"',
  '("Allow", "GET, HEAD")',
  'metrics_http_response_allows_get_and_head_only',
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

for (const phrase of [
  'ObserveDependencyFromContext',
  'postgres',
  'journal_create',
  'journal_list',
  'journal_read',
]) {
  assert.ok(journalHTTP.includes(phrase), `Journal HTTP observability missing ${phrase}`);
}

for (const phrase of [
  'ObserveDependencyFromContext',
  'postgres',
  'auth_register',
  'auth_login',
  'auth_issue_refresh_token',
  'auth_refresh',
  'auth_logout',
  'auth_mfa_enroll',
  'auth_mfa_verify',
  'mfa_required',
  'invalid_or_expired',
]) {
  assert.ok(authHTTP.includes(phrase), `Auth HTTP observability missing ${phrase}`);
}

for (const phrase of [
  'ObserveDependencyFromContext',
  'postgres',
  'redis',
  'room_membership',
  'room_get_latest',
]) {
  assert.ok(roomsHTTP.includes(phrase), `Room HTTP observability missing ${phrase}`);
}

for (const phrase of [
  'ObserveDependencyFromContext',
  'ObserveWebSocketActiveConnectionFromContext',
  'redis',
  'room_append_event',
  'websocket',
  'room_broadcast',
  'dropped',
]) {
  assert.ok(roomsWSS.includes(phrase), `Room WebSocket observability missing ${phrase}`);
}

for (const phrase of [
  'ObserveDependencyFromContext',
  'ObserveAIInferenceFromContext',
  'ai_provider',
  'chat_completion',
  'timeout_or_network_error',
  'verification_failed',
]) {
  assert.ok(llmClient.includes(phrase), `LLM observability missing ${phrase}`);
}

for (const phrase of [
  'ObserveDependencyFromContext',
  'zoom',
  'create_meeting',
  'circuit_open_fallback',
  'get_meeting_status',
]) {
  assert.ok(zoomClient.includes(phrase), `Zoom observability missing ${phrase}`);
}

for (const phrase of [
  'ObserveDependencyFromContext',
  'abuse_limiter',
  'allowed',
  'limited',
]) {
  assert.ok(abuseLimiter.includes(phrase), `Abuse limiter observability missing ${phrase}`);
}

for (const [artifactName, artifactSource] of [
  ['observability probe', observabilityProbe],
  ['staging evidence recorder', recordStagingEvidence],
  ['staging evidence validator', validateStagingEvidence],
]) {
  for (const phrase of [
    'api-prometheus-metrics',
    'websocket_active_connections_count',
    'dependency="websocket",operation="room_broadcast",status="dropped"',
    'ai_inference_duration_seconds_sum',
    'ai_inference_duration_seconds_count',
    'dashboard-import',
    'alert-rules-loaded',
    'ScriptureForgeAIInferenceLatencyElevated',
    'ScriptureForgeRoomBroadcastDrops',
    'ai_inference_duration_seconds',
  ]) {
    assert.ok(artifactSource.includes(phrase), `${artifactName} missing staging OBS metric evidence marker ${phrase}`);
  }
}

assert.ok(observabilityProbe.includes('STAGING_METRICS_AUTH_TOKEN'), 'observability probe missing API metrics auth configuration');
assert.ok(observabilityProbe.includes('probeContainsAllWithAuth'), 'observability probe missing authenticated API metrics request');

for (const phrase of [
  'timestamp=',
  'severity=',
  'tenant_id=',
  'user_id=',
  'role=',
]) {
  assert.ok(observabilityProbe.includes(phrase), `observability probe missing concrete log principal marker ${phrase}`);
  assert.ok(recordStagingEvidence.includes(phrase), `staging evidence recorder missing concrete log principal marker ${phrase}`);
}
assert.ok(validateStagingEvidence.includes('timestamp=[^\\s,;]+'), 'staging evidence validator missing concrete log timestamp regex');
assert.ok(validateStagingEvidence.includes('severity=[A-Za-z0-9_.:-]+'), 'staging evidence validator missing concrete log severity regex');
for (const phrase of [
  'tenant_id=',
  'user_id=',
  'role=',
]) {
  assert.ok(validateStagingEvidence.includes(`${phrase}[A-Za-z0-9_.:-]+`), `staging evidence validator missing concrete log principal regex for ${phrase}`);
}

for (const phrase of [
  'STAGING_OBSERVED_TENANT_ID',
  'STAGING_OBSERVED_USER_ID',
  'STAGING_OBSERVED_ROLE',
  'OBS-OTEL-001 report must include tenant_id as a concrete token',
]) {
  assert.ok(observabilityProbe.includes(phrase) || recordStagingEvidence.includes(phrase), `OBS tenant-principal evidence contract missing ${phrase}`);
}

  assert.ok(
    observabilityProbe.includes('normalizeExternalStagingURL(cfg.RustMetricsURL, "rust-metrics-url")'),
    'observability probe must require Rust metrics to come from an external staging artifact URL',
  );

for (const phrase of [
  'OBS-OTEL-001',
  'OBS-ALERT-001',
  'websocket_active_connections_count',
  'dependency="websocket",operation="room_broadcast",status="dropped"',
  'ai_inference_duration_seconds',
  'room broadcast drops',
]) {
  assert.ok(stagingEvidenceExample.includes(phrase), `staging evidence example missing OBS contract marker ${phrase}`);
}

  return observabilityProofMarkers;
}

export async function validateObservabilityArtifacts(paths = observabilityArtifactPaths) {
  return validateObservabilitySources(await loadObservabilitySources(paths));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const markers = await validateObservabilityArtifacts();
  console.log(`observability artifacts validated: ${markers.join(', ')}`);
}
