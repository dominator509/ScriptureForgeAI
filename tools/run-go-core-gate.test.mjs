import assert from 'node:assert/strict';
import test from 'node:test';
import {
  defaultGoBin,
  goArgsForMode,
  goTestProofMarkers,
  goTestRequiredAbuseTests,
  goTestRequiredObservabilityTests,
  goTestRequiredWebSocketTests,
  goVetProofMarkers,
  parseArgs,
  runGoCoreGate,
  validateGoTestOutput,
} from './run-go-core-gate.mjs';

test('parseArgs supports mode, bin, and cwd', () => {
  const args = parseArgs(['--mode', 'test', '--bin=go', '--cwd', 'repo']);
  assert.equal(args.mode, 'test');
  assert.equal(args.bin, 'go');
  assert.equal(args.cwd, 'repo');
});

test('defaultGoBin resolves repo-local Go by platform', () => {
  assert.equal(defaultGoBin('win32'), '.\\.tools\\go\\bin\\go.exe');
  assert.equal(defaultGoBin('linux'), './.tools/go/bin/go');
});

test('goArgsForMode defines all-package test and vet gates', () => {
  assert.deepEqual(goArgsForMode('test'), {
    args: ['test', './...', '-count=1', '-timeout=90s', '-v'],
    proofName: 'go-test-gate',
    markers: goTestProofMarkers,
  });
  assert.deepEqual(goArgsForMode('vet'), {
    args: ['vet', './...'],
    proofName: 'go-vet-gate',
    markers: goVetProofMarkers,
  });
  assert.throws(() => goArgsForMode('fmt'), /unsupported Go gate mode/);
});

test('runGoCoreGate runs go test with release proof markers', () => {
  const calls = [];
  const result = runGoCoreGate({
    mode: 'test',
    bin: 'go',
    cwd: 'repo',
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: requiredGoTestPassOutput(), stderr: '' };
    },
    env: { GOCACHE: '.gocache', GO_ENV: 'testing' },
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.proofName, 'go-test-gate');
  assert.deepEqual(result.markers, goTestProofMarkers);
  assert.equal(calls[0].command, 'go');
  assert.deepEqual(calls[0].args, ['test', './...', '-count=1', '-timeout=90s', '-v']);
  assert.equal(calls[0].options.env.GO_ENV, 'testing');
});

test('validateGoTestOutput requires WebSocket production-behavior PASS lines', () => {
  assert.doesNotThrow(() => validateGoTestOutput(requiredGoTestPassOutput()));
  assert.throws(
    () => validateGoTestOutput(requiredGoTestPassOutput().replace('--- PASS: TestLiveRoomRejectsDisallowedOrigin', '--- SKIP: TestLiveRoomRejectsDisallowedOrigin')),
    /skipped: TestLiveRoomRejectsDisallowedOrigin/,
  );
  assert.throws(
    () => validateGoTestOutput(requiredGoTestPassOutput().replace('--- PASS: TestRoomStateHandlerFailsClosedWhenStateManagerMissing', '--- RUN: TestRoomStateHandlerFailsClosedWhenStateManagerMissing')),
    /missing PASS lines: TestRoomStateHandlerFailsClosedWhenStateManagerMissing/,
  );
});

test('validateGoTestOutput requires mounted abuse route PASS lines', () => {
  assert.doesNotThrow(() => validateGoTestOutput(requiredGoTestPassOutput()));
  assert.throws(
    () => validateGoTestOutput(requiredGoTestPassOutput().replace('--- PASS: TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/journal_create', '--- SKIP: TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/journal_create')),
    /skipped: TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles\/journal_create/,
  );
  assert.throws(
    () => validateGoTestOutput(requiredGoTestPassOutput().replace('--- PASS: TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/websocket_stream', '--- RUN: TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/websocket_stream')),
    /missing PASS lines: TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles\/websocket_stream/,
  );
});

test('validateGoTestOutput requires observability trace and metrics PASS lines', () => {
  assert.doesNotThrow(() => validateGoTestOutput(requiredGoTestPassOutput()));
  assert.throws(
    () => validateGoTestOutput(requiredGoTestPassOutput().replace('--- PASS: TestMetricsHandlerServesPrometheusText', '--- SKIP: TestMetricsHandlerServesPrometheusText')),
    /skipped: TestMetricsHandlerServesPrometheusText/,
  );
  assert.throws(
    () => validateGoTestOutput(requiredGoTestPassOutput().replace('--- PASS: TestObserveDependencyFromContextAddsTraceSpan', '--- RUN: TestObserveDependencyFromContextAddsTraceSpan')),
    /missing PASS lines: TestObserveDependencyFromContextAddsTraceSpan/,
  );
});

test('runGoCoreGate rejects successful go test output without required WebSocket proof', () => {
  const result = runGoCoreGate({
    mode: 'test',
    bin: 'go',
    spawnSyncImpl() {
      return { status: 0, stdout: 'ok scriptureforge/internal/ports\n', stderr: '' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /go-test-gate missing required WebSocket production-behavior proof/);
});

test('runGoCoreGate rejects successful go test output without required abuse route proof', () => {
  const result = runGoCoreGate({
    mode: 'test',
    bin: 'go',
    spawnSyncImpl() {
      return { status: 0, stdout: requiredWebSocketPassOutput(), stderr: '' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /go-test-gate missing required abuse\/rate-limit route proof/);
});

test('runGoCoreGate rejects successful go test output without required observability proof', () => {
  const result = runGoCoreGate({
    mode: 'test',
    bin: 'go',
    spawnSyncImpl() {
      return { status: 0, stdout: requiredWebSocketPassOutput() + requiredAbusePassOutput(), stderr: '' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /go-test-gate missing required observability trace\/metrics proof/);
});

test('runGoCoreGate runs go vet with static-analysis proof markers', () => {
  const result = runGoCoreGate({
    mode: 'vet',
    bin: 'go',
    spawnSyncImpl() {
      return { status: 0, stdout: '', stderr: '' };
    },
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.proofName, 'go-vet-gate');
  assert.deepEqual(result.markers, goVetProofMarkers);
  assert.deepEqual(result.args, ['vet', './...']);
});

test('runGoCoreGate propagates failing Go output', () => {
  const result = runGoCoreGate({
    mode: 'test',
    bin: 'go',
    spawnSyncImpl() {
      return { status: 1, stdout: '', stderr: 'FAIL scriptureforge/internal/ports\n' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /FAIL scriptureforge\/internal\/ports/);
});

function requiredWebSocketPassOutput() {
  return `${goTestRequiredWebSocketTests.map((testName) => `--- PASS: ${testName} (0.00s)`).join('\n')}\nok scriptureforge/internal/ports\n`;
}

function requiredAbusePassOutput() {
  return `${goTestRequiredAbuseTests.map((testName) => `--- PASS: ${testName} (0.00s)`).join('\n')}\nok scriptureforge/cmd/platform-engine\n`;
}

function requiredObservabilityPassOutput() {
  return `${goTestRequiredObservabilityTests.map((testName) => `--- PASS: ${testName} (0.00s)`).join('\n')}\nok scriptureforge/internal/domain/observability\n`;
}

function requiredGoTestPassOutput() {
  return `${requiredWebSocketPassOutput()}${requiredAbusePassOutput()}${requiredObservabilityPassOutput()}`;
}
