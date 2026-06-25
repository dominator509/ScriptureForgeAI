import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';

function usage() {
  return [
    'Usage:',
    '  node tools/record-staging-evidence.mjs --manifest <path> --probe-report <path> --artifact <path-or-url> --command <command>',
    '  node tools/record-staging-evidence.mjs --manifest <path> --item-id <ID> --artifact <path-or-url> --command <command> --summary <summary> [--observed-at <ISO-UTC>]',
    '  node tools/record-staging-evidence.mjs --manifest <path> --item-id <ID> --status blocked|failed --owner <owner> --blocker <reason>',
    '  node tools/record-staging-evidence.mjs --manifest <path> --item-id <ID> --status accepted_risk --decision-ref <record>',
    '',
    'The probe report must include threshold_pass=true and evidence_items[].',
  ].join('\n');
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith('--') || value == null) {
      throw new Error(usage());
    }
    args[key.slice(2)] = value;
  }
  if (!args.manifest) {
    throw new Error(`missing --manifest\n${usage()}`);
  }
  if (!args['probe-report'] && !args['item-id']) {
    throw new Error(`missing --probe-report or --item-id\n${usage()}`);
  }
  if (args['probe-report'] && args['item-id']) {
    throw new Error(`choose only one of --probe-report or --item-id\n${usage()}`);
  }
  if (args['probe-report']) {
    for (const required of ['artifact', 'command']) {
      if (!args[required]) {
        throw new Error(`missing --${required}\n${usage()}`);
      }
    }
  }
  if (args['item-id'] && !args.status) {
    for (const required of ['artifact', 'command', 'summary']) {
      if (!args[required]) {
        throw new Error(`missing --${required} for --item-id evidence mode\n${usage()}`);
      }
    }
  }
  if (args.status && !['blocked', 'failed', 'accepted_risk'].includes(args.status)) {
    throw new Error(`invalid --status ${args.status}\n${usage()}`);
  }
  if ((args.status === 'blocked' || args.status === 'failed') && (!args.owner || !args.blocker)) {
    throw new Error(`--status ${args.status} requires --owner and --blocker\n${usage()}`);
  }
  if (args.status === 'accepted_risk' && !args['decision-ref']) {
    throw new Error(`--status accepted_risk requires --decision-ref\n${usage()}`);
  }
  return args;
}

function summarizeProbeReport(report) {
  const passed = report.probes?.filter((probe) => probe.passed).length ?? 0;
  const failed = report.probes?.filter((probe) => !probe.passed).length ?? 0;
  const names = report.probes?.map((probe) => `${probe.name}:${probe.passed ? 'pass' : 'fail'}`).join(', ') ?? 'no probes';
  return `${passed} probes passed, ${failed} probes failed (${names})`;
}

const productionPerformanceTargets = {
  'PERF-HTTP-001': {
    minRPS: 5000,
    maxP99MS: 200,
    targetPattern: /^https:\/\//,
    targetDescription: 'HTTPS staging target',
  },
  'PERF-WS-001': {
    minRPS: 500,
    maxP99MS: 200,
    targetPattern: /^wss:\/\//,
    targetDescription: 'WSS staging target',
  },
};

function assertNoLocalTarget(report, id) {
  const target = String(report.target ?? '');
  assert.ok(target.length > 0, `${id} load report must include target`);
  assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(target), `${id} load report target must not be local/self-test: ${target}`);
}

function validatePerformanceEvidence(report) {
  const evidenceItems = report.evidence_items ?? [];
  for (const [id, target] of Object.entries(productionPerformanceTargets)) {
    if (!evidenceItems.includes(id)) {
      continue;
    }
    assertNoLocalTarget(report, id);
    assert.match(String(report.target), target.targetPattern, `${id} load report must use ${target.targetDescription}`);
    assert.equal(typeof report.min_rps, 'number', `${id} load report must include configured min_rps`);
    assert.equal(typeof report.max_p99_ms, 'number', `${id} load report must include configured max_p99_ms`);
    assert.equal(typeof report.rps, 'number', `${id} load report must include observed rps`);
    assert.equal(typeof report.p99_ms, 'number', `${id} load report must include observed p99_ms`);
    assert.ok(report.min_rps >= target.minRPS, `${id} min_rps ${report.min_rps} is below required ${target.minRPS}`);
    assert.ok(report.max_p99_ms > 0 && report.max_p99_ms <= target.maxP99MS, `${id} max_p99_ms ${report.max_p99_ms} must be <= ${target.maxP99MS}`);
    assert.ok(report.rps >= target.minRPS, `${id} observed rps ${report.rps} is below required ${target.minRPS}`);
    assert.ok(report.p99_ms <= target.maxP99MS, `${id} observed p99_ms ${report.p99_ms} is above required ${target.maxP99MS}`);
  }
  if (evidenceItems.includes('DATA-REDIS-001')) {
    assert.ok(evidenceItems.includes('PERF-WS-001'), 'DATA-REDIS-001 load evidence must be paired with PERF-WS-001');
  }
  if (evidenceItems.includes('PERF-HTTP-001')) {
    const httpReplicaArtifactURL = String(report.http_replica_artifact_url ?? '');
    assert.match(httpReplicaArtifactURL, /^https:\/\//, 'PERF-HTTP-001 report must include HTTPS http_replica_artifact_url');
    assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(httpReplicaArtifactURL), `PERF-HTTP-001 http_replica_artifact_url must not be local/self-test: ${httpReplicaArtifactURL}`);
    const dependencyTelemetryArtifactURL = String(report.dependency_telemetry_artifact_url ?? '');
    assert.match(dependencyTelemetryArtifactURL, /^https:\/\//, 'PERF-HTTP-001 report must include HTTPS dependency_telemetry_artifact_url');
    assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(dependencyTelemetryArtifactURL), `PERF-HTTP-001 dependency_telemetry_artifact_url must not be local/self-test: ${dependencyTelemetryArtifactURL}`);
  }
  if (evidenceItems.includes('PERF-WS-001')) {
    const replicaArtifactURL = String(report.ws_replica_artifact_url ?? '');
    assert.match(replicaArtifactURL, /^https:\/\//, 'PERF-WS-001 report must include HTTPS ws_replica_artifact_url');
    assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(replicaArtifactURL), `PERF-WS-001 ws_replica_artifact_url must not be local/self-test: ${replicaArtifactURL}`);
  }
  if (evidenceItems.includes('DATA-REDIS-001')) {
    const redisTelemetryArtifactURL = String(report.redis_telemetry_artifact_url ?? '');
    assert.match(redisTelemetryArtifactURL, /^https:\/\//, 'DATA-REDIS-001 report must include HTTPS redis_telemetry_artifact_url');
    assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(redisTelemetryArtifactURL), `DATA-REDIS-001 redis_telemetry_artifact_url must not be local/self-test: ${redisTelemetryArtifactURL}`);
  }
}

function validateTLSEvidence(report) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('DEPLOY-TLS-001')) {
    return;
  }
  for (const [field, label] of [
    ['dns_artifact_url', 'DNS'],
    ['acm_artifact_url', 'ACM'],
  ]) {
    const artifactURL = String(report[field] ?? '');
    assert.match(artifactURL, /^https:\/\//, `DEPLOY-TLS-001 report must include HTTPS ${field}`);
    assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(artifactURL), `DEPLOY-TLS-001 ${label} artifact must not be local/self-test: ${artifactURL}`);
  }
}

function validateKubernetesEvidence(report) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('DEPLOY-K8S-001')) {
    return;
  }
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const probesByName = new Map(probes.map((probe) => [probe.name, probe]));
  for (const name of ['kubernetes-rollout-status', 'kubernetes-workload-resources']) {
    const probe = probesByName.get(name);
    assert.ok(probe, `DEPLOY-K8S-001 report must include ${name} probe`);
    assert.equal(probe.passed, true, `${name} must pass`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https:\/\//, `${name} target must be an HTTPS artifact URL`);
    assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(target), `${name} target must not be local/self-test: ${target}`);
  }
}

function validateWebClientEvidence(report) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('CLIENT-WEB-001')) {
    return;
  }
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const webRoot = probes.find((probe) => probe.name === 'web-root');
  assert.ok(webRoot, 'CLIENT-WEB-001 report must include web-root probe');
  assert.equal(webRoot.passed, true, 'web-root must pass');
  const webTarget = String(report.web_target ?? '');
  assert.match(webTarget, /^https:\/\//, 'CLIENT-WEB-001 report must include HTTPS web_target');
  assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(webTarget), `CLIENT-WEB-001 web_target must not be local/self-test: ${webTarget}`);
  for (const [field, label] of [
    ['web_auth_smoke_url', 'auth browser smoke'],
    ['web_journal_smoke_url', 'journal browser smoke'],
    ['web_room_smoke_url', 'room browser smoke'],
  ]) {
    const artifactURL = String(report[field] ?? '');
    assert.match(artifactURL, /^https:\/\//, `CLIENT-WEB-001 report must include HTTPS ${field}`);
    assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(artifactURL), `CLIENT-WEB-001 ${label} artifact must not be local/self-test: ${artifactURL}`);
  }
}

function validateAbuseEvidence(report) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('ABUSE-LIMIT-001')) {
    return;
  }
  const apiTarget = String(report.api_target ?? '');
  assert.match(apiTarget, /^https:\/\//, 'ABUSE-LIMIT-001 report must use HTTPS api_target');
  assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(apiTarget), `ABUSE-LIMIT-001 api_target must not be local/self-test: ${apiTarget}`);
  const configArtifactURL = String(report.config_artifact_url ?? '');
  assert.match(configArtifactURL, /^https:\/\//, 'ABUSE-LIMIT-001 report must include HTTPS config_artifact_url');
  assert.ok(!/localhost|127\.0\.0\.1|\[?::1\]?/i.test(configArtifactURL), `ABUSE-LIMIT-001 config_artifact_url must not be local/self-test: ${configArtifactURL}`);

  const requiredProfiles = new Set([
    'auth-rate-limit',
    'ai-rate-limit',
    'journal-rate-limit',
    'rooms-rate-limit',
    'websocket-rate-limit',
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, requiredProfiles.size, 'ABUSE-LIMIT-001 report must include exactly the required abuse profiles');
  for (const probe of probes) {
    assert.ok(requiredProfiles.delete(probe.name), `ABUSE-LIMIT-001 report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 429, `${probe.name} must observe HTTP 429`);
    assert.ok(String(probe.retry_after ?? '').trim(), `${probe.name} must include Retry-After`);
    assert.ok(String(probe.rate_limit ?? '').trim(), `${probe.name} must include X-RateLimit-Limit`);
    assert.ok(String(probe.rate_limit_remaining ?? '').trim(), `${probe.name} must include X-RateLimit-Remaining`);
    assert.ok(String(probe.rate_limit_reset ?? '').trim(), `${probe.name} must include X-RateLimit-Reset`);
  }
  assert.equal(requiredProfiles.size, 0, `ABUSE-LIMIT-001 report missing profiles: ${[...requiredProfiles].join(', ')}`);
}

async function readJSON(path) {
  const content = await readFile(path, 'utf8');
  return JSON.parse(content.replace(/^\uFEFF/, ''));
}

function recordEvidence(manifest, report, artifact, command) {
  assert.equal(report.threshold_pass, true, 'probe report threshold_pass must be true before recording passed evidence');
  assert.ok(Array.isArray(report.evidence_items), 'probe report must include evidence_items');
  assert.ok(report.evidence_items.length > 0, 'probe report must include at least one evidence item');
  assert.match(report.observed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'probe report observed_at must be ISO UTC without milliseconds');
  validateTLSEvidence(report);
  validateKubernetesEvidence(report);
  validateWebClientEvidence(report);
  validatePerformanceEvidence(report);
  validateAbuseEvidence(report);

  const itemsById = new Map(manifest.items.map((item) => [item.id, item]));
  for (const id of report.evidence_items) {
    const item = itemsById.get(id);
    assert.ok(item, `manifest missing evidence item ${id}`);
    item.status = 'passed';
    item.evidence ??= [];
    const alreadyRecorded = item.evidence.some((entry) => entry.artifact === artifact && entry.command_or_probe === command);
    if (!alreadyRecorded) {
      item.evidence.push({
        observed_at: report.observed_at,
        command_or_probe: command,
        artifact,
        result_summary: summarizeProbeReport(report),
      });
    }
  }
  manifest.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  return manifest;
}

function recordManualEvidence(manifest, itemID, artifact, command, summary, observedAt) {
  assert.match(observedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'observedAt must be ISO UTC without milliseconds');
  assert.ok(summary.trim().length > 0, 'summary must not be empty');
  const item = manifest.items.find((candidate) => candidate.id === itemID);
  assert.ok(item, `manifest missing evidence item ${itemID}`);
  item.status = 'passed';
  item.evidence ??= [];
  const alreadyRecorded = item.evidence.some((entry) => entry.artifact === artifact && entry.command_or_probe === command);
  if (!alreadyRecorded) {
    item.evidence.push({
      observed_at: observedAt,
      command_or_probe: command,
      artifact,
      result_summary: summary,
    });
  }
  manifest.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  return manifest;
}

function recordStatus(manifest, itemID, status, details) {
  const item = manifest.items.find((candidate) => candidate.id === itemID);
  assert.ok(item, `manifest missing evidence item ${itemID}`);
  assert.ok(['blocked', 'failed', 'accepted_risk'].includes(status), `unsupported status ${status}`);
  item.status = status;
  delete item.evidence;
  if (status === 'blocked' || status === 'failed') {
    assert.ok(details.owner?.trim(), `${status} status requires owner`);
    assert.ok(details.blocker?.trim(), `${status} status requires blocker`);
    item.owner = details.owner;
    item.blocker = details.blocker;
    delete item.decision_ref;
  }
  if (status === 'accepted_risk') {
    assert.ok(details.decisionRef?.trim(), 'accepted_risk status requires decisionRef');
    item.decision_ref = details.decisionRef;
    delete item.owner;
    delete item.blocker;
  }
  manifest.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  return manifest;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = await readJSON(args.manifest);
  let updated;
  let recordedCount;
  if (args['probe-report']) {
    const report = await readJSON(args['probe-report']);
    updated = recordEvidence(manifest, report, args.artifact, args.command);
    recordedCount = report.evidence_items.length;
  } else {
    if (args.status) {
      updated = recordStatus(manifest, args['item-id'], args.status, {
        owner: args.owner,
        blocker: args.blocker,
        decisionRef: args['decision-ref'],
      });
    } else {
      const observedAt = args['observed-at'] ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
      updated = recordManualEvidence(manifest, args['item-id'], args.artifact, args.command, args.summary, observedAt);
    }
    recordedCount = 1;
  }
  await writeFile(args.manifest, `${JSON.stringify(updated, null, 2)}\n`);
  console.log(`recorded ${recordedCount} evidence item(s) into ${args.manifest}`);
}

if (import.meta.url === `file://${process.argv[1].replaceAll('\\', '/')}` || process.argv[1]?.endsWith('record-staging-evidence.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

export { parseArgs, recordEvidence, recordManualEvidence, recordStatus, summarizeProbeReport };
