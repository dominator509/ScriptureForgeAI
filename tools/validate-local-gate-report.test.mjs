import assert from 'node:assert/strict';
import test from 'node:test';
import { gateDefinitions } from './run-local-gates.mjs';
import { parseArgs, validateLocalGateReport } from './validate-local-gate-report.mjs';

test('parseArgs supports report path and relaxed validation flags', () => {
  const args = parseArgs(['--report', 'artifacts/report.json', '--allow-dry-run', '--allow-subset']);
  assert.equal(args.report, 'artifacts/report.json');
  assert.equal(args.allowDryRun, true);
  assert.equal(args.requireAllGates, false);
});

test('validateLocalGateReport accepts a complete passing report', () => {
  const report = completeReport();
  const result = validateLocalGateReport(report);
  assert.equal(result.gateCount, gateDefinitions.length);
  assert.equal(result.dryRun, false);
  assert.equal(result.gitHead, '0123456789abcdef0123456789abcdef01234567');
});

test('validateLocalGateReport rejects dry-run reports unless allowed', () => {
  const report = completeReport({ dryRun: true });
  assert.throws(() => validateLocalGateReport(report), /dry-run/);
  assert.doesNotThrow(() => validateLocalGateReport(report, { allowDryRun: true }));
});

test('validateLocalGateReport rejects failed or incomplete reports', () => {
  assert.throws(
    () => validateLocalGateReport(completeReport({ failedGateID: 'go-vet' })),
    /threshold_pass must be true/,
  );
  assert.throws(
    () => validateLocalGateReport(partialReport()),
    /gates_total must match results length/,
  );
});

test('validateLocalGateReport rejects missing git head', () => {
  const report = completeReport();
  delete report.git_head;
  assert.throws(() => validateLocalGateReport(report), /git_head/);
});

test('validateLocalGateReport can validate focused subset reports', () => {
  const report = partialReport({ consistentTotals: true });
  assert.throws(() => validateLocalGateReport(report), /missing/);
  assert.doesNotThrow(() => validateLocalGateReport(report, { requireAllGates: false }));
});

function completeReport({ dryRun = false, failedGateID = '' } = {}) {
  const results = gateDefinitions.map((gate, index) => ({
    id: gate.id,
    command: gate.command.join(' '),
    cwd: gate.cwd ?? '.',
    skipped: dryRun,
    exit_code: gate.id === failedGateID ? 1 : 0,
    duration_ms: index,
    stdout_tail: '',
    stderr_tail: '',
  }));
  const failed = results.filter((result) => result.exit_code !== 0).length;
  return {
    schema_version: 1,
    git_head: '0123456789abcdef0123456789abcdef01234567',
    observed_at: '2026-06-25T12:00:00Z',
    duration_ms: 100,
    threshold_pass: failed === 0,
    dry_run: dryRun,
    gates_total: results.length,
    gates_run: results.length,
    gates_failed: failed,
    results,
  };
}

function partialReport({ consistentTotals = false } = {}) {
  const results = completeReport().results.slice(0, 2);
  return {
    schema_version: 1,
    git_head: '0123456789abcdef0123456789abcdef01234567',
    observed_at: '2026-06-25T12:00:00Z',
    duration_ms: 100,
    threshold_pass: true,
    dry_run: false,
    gates_total: consistentTotals ? results.length : gateDefinitions.length,
    gates_run: results.length,
    gates_failed: 0,
    results,
  };
}
