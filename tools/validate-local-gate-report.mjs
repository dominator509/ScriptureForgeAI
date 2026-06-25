import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gateDefinitions } from './run-local-gates.mjs';

const requiredGateIds = new Set(gateDefinitions.map((gate) => gate.id));

export function validateLocalGateReport(report, { allowDryRun = false, requireAllGates = true } = {}) {
  assert.equal(report.schema_version, 1, 'local gate report schema_version must be 1');
  assert.match(report.observed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'observed_at must be ISO UTC without milliseconds');
  assert.equal(typeof report.threshold_pass, 'boolean', 'threshold_pass is required');
  assert.equal(typeof report.dry_run, 'boolean', 'dry_run is required');
  assert.equal(typeof report.gates_total, 'number', 'gates_total is required');
  assert.equal(typeof report.gates_run, 'number', 'gates_run is required');
  assert.equal(typeof report.gates_failed, 'number', 'gates_failed is required');
  assert.ok(Array.isArray(report.results), 'results must be an array');

  if (!allowDryRun) {
    assert.equal(report.dry_run, false, 'dry-run reports cannot satisfy local gate evidence');
  }
  assert.equal(report.threshold_pass, true, 'local gate report threshold_pass must be true');
  assert.equal(report.gates_failed, 0, 'local gate report must have zero failed gates');
  assert.equal(report.gates_run, report.results.length, 'gates_run must match results length');
  assert.equal(report.gates_total, report.results.length, 'gates_total must match results length');

  const seen = new Set();
  for (const result of report.results) {
    assert.equal(typeof result.id, 'string', 'gate result id is required');
    assert.ok(!seen.has(result.id), `duplicate local gate result ${result.id}`);
    seen.add(result.id);
    assert.ok(requiredGateIds.has(result.id), `unknown local gate result ${result.id}`);
    assert.equal(typeof result.command, 'string', `${result.id} command is required`);
    assert.equal(typeof result.cwd, 'string', `${result.id} cwd is required`);
    assert.equal(result.exit_code, 0, `${result.id} exit_code must be 0`);
    assert.equal(typeof result.duration_ms, 'number', `${result.id} duration_ms is required`);
    assert.ok(result.duration_ms >= 0, `${result.id} duration_ms must be non-negative`);
  }

  if (requireAllGates) {
    for (const gateID of requiredGateIds) {
      assert.ok(seen.has(gateID), `local gate report missing ${gateID}`);
    }
  }

  return {
    gateCount: report.results.length,
    dryRun: report.dry_run,
  };
}

export function parseArgs(argv) {
  const args = {
    report: 'artifacts/local-gate-report.json',
    allowDryRun: false,
    requireAllGates: true,
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--report') {
      args.report = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--allow-dry-run') {
      args.allowDryRun = true;
    } else if (argv[i] === '--allow-subset') {
      args.requireAllGates = false;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = JSON.parse(await readFile(args.report, 'utf8'));
  const result = validateLocalGateReport(report, args);
  console.log(`local gate report validated: ${args.report} (${result.gateCount} gates)`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-local-gate-report.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
