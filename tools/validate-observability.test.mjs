import assert from 'node:assert/strict';
import { before, describe, it } from 'node:test';

import {
  loadObservabilitySources,
  validateObservabilitySources,
} from './validate-observability.mjs';

let baseSources;

function cloneSources(overrides = {}) {
  return {
    ...baseSources,
    dashboard: JSON.parse(JSON.stringify(baseSources.dashboard)),
    ...overrides,
  };
}

function expectValidationFailure(sources, pattern) {
  assert.throws(() => validateObservabilitySources(sources), pattern);
}

describe('validate-observability', () => {
  before(async () => {
    baseSources = await loadObservabilitySources();
  });

  it('accepts the current observability artifacts', () => {
    assert.deepEqual(validateObservabilitySources(cloneSources()), [
      'dashboard_metrics=true',
      'alert_rules=true',
      'trace_id_logs=true',
      'trace_id_shape_guard=true',
      'structured_log_canonical_fields=true',
      'metrics_endpoint=true',
      'dependency_spans=true',
      'websocket_profile_metrics=true',
      'ai_profile_metrics=true',
      'rust_metrics=true',
      'otel_env_wiring=true',
      'staging_evidence_contract=true',
    ]);
  });

  it('rejects dashboard drift that drops AI inference metrics', () => {
    const dashboard = JSON.parse(
      JSON.stringify(baseSources.dashboard).replaceAll('ai_inference_duration_seconds', 'ai_metric_removed'),
    );

    expectValidationFailure(cloneSources({ dashboard }), /dashboard missing ai_inference_duration_seconds/);
  });

  it('rejects alert drift that drops room broadcast drop coverage', () => {
    const alerts = baseSources.alerts.replace('alert: ScriptureForgeRoomBroadcastDrops', 'alert: RemovedRoomBroadcastDrops');

    expectValidationFailure(cloneSources({ alerts }), /missing alert ScriptureForgeRoomBroadcastDrops/);
  });

  it('rejects API trace ID guard drift', () => {
    const apiObservability = baseSources.apiObservability.replaceAll('normalizeTraceID', 'traceIDNormalizerRemoved');

    expectValidationFailure(cloneSources({ apiObservability }), /API structured log observability missing normalizeTraceID/);
  });

  it('rejects dependency span error-classification drift', () => {
    const apiObservability = baseSources.apiObservability.replace('strings.Contains(status, "dropped")', 'status == "drop"');

    expectValidationFailure(cloneSources({ apiObservability }), /API structured log observability missing strings\.Contains\(status, "dropped"\)/);
  });

  it('rejects canonical structured log field drift', () => {
    const apiObservability = baseSources.apiObservability.replace('Timestamp             string `json:"timestamp"`', 'LegacyAtOnly          string `json:"at"`');

    expectValidationFailure(cloneSources({ apiObservability }), /API structured log observability missing Timestamp\s+string `json:"timestamp"`/);
  });

  it('rejects Rust engine observability drift', () => {
    const rustEngine = baseSources.rustEngine.replaceAll('traceparent_from_request', 'traceparent_removed');

    expectValidationFailure(cloneSources({ rustEngine }), /Rust engine observability missing traceparent_from_request/);
  });

  it('rejects Rust metrics method restriction drift', () => {
    const rustEngine = baseSources.rustEngine.replaceAll('"405 Method Not Allowed"', '"404 Not Found"');

    expectValidationFailure(cloneSources({ rustEngine }), /Rust engine observability missing "405 Method Not Allowed"/);
  });

  it('rejects staging evidence contract drift for external Rust metrics proof', () => {
    const observabilityProbe = baseSources.observabilityProbe.replace(
      'normalizeExternalStagingURL(cfg.RustMetricsURL, "rust-metrics-url")',
      'cfg.RustMetricsURL',
    );

    expectValidationFailure(cloneSources({ observabilityProbe }), /Rust metrics to come from an external staging artifact URL/);
  });

  it('rejects observability evidence drift that allows bare tenant principal log markers', () => {
    const validateStagingEvidence = baseSources.validateStagingEvidence
      .replace('tenant_id=[A-Za-z0-9_.:-]+', 'tenant_id=');

    expectValidationFailure(cloneSources({ validateStagingEvidence }), /concrete log principal regex for tenant_id=/);
  });
});
