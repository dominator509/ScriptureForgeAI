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
  validatePerformanceEvidence(report);

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
