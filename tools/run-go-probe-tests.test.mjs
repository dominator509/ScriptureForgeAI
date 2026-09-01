import assert from 'node:assert/strict';
import test from 'node:test';
import {
  defaultGoBin,
  goProbePackages,
  goProbeProofMarkers,
  parseArgs,
  runGoProbeTests,
  validateGoProbeOutput,
} from './run-go-probe-tests.mjs';

test('parseArgs supports bin and cwd', () => {
  const args = parseArgs(['--bin', 'go', '--cwd=repo']);
  assert.equal(args.bin, 'go');
  assert.equal(args.cwd, 'repo');
});

test('defaultGoBin resolves repo-local Go by platform', () => {
  assert.equal(defaultGoBin('win32'), '.\\.tools\\go\\bin\\go.exe');
  assert.equal(defaultGoBin('linux'), './.tools/go/bin/go');
});

test('runGoProbeTests runs every production evidence probe package with count one', () => {
  const calls = [];
  const result = runGoProbeTests({
    bin: 'go',
    cwd: 'repo',
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: requiredProbePackageOutput(), stderr: '' };
    },
    env: { GOCACHE: '.gocache' },
  });

  assert.equal(result.exitCode, 0);
  assert.deepEqual(result.markers, goProbeProofMarkers);
  assert.equal(calls[0].command, 'go');
  assert.deepEqual(calls[0].args, ['test', ...goProbePackages, '-count=1']);
  assert.equal(calls[0].options.cwd, 'repo');
  assert.equal(calls[0].options.env.GOCACHE, '.gocache');
});

test('validateGoProbeOutput requires every production evidence probe package result', () => {
  assert.doesNotThrow(() => validateGoProbeOutput(requiredProbePackageOutput()));
  assert.throws(
    () => validateGoProbeOutput(requiredProbePackageOutput().replace('ok scriptureforge/tools/loadtest', '')),
    /missing package result lines: .*\.\/tools\/loadtest/,
  );
});

test('runGoProbeTests rejects successful output missing a probe package result', () => {
  const result = runGoProbeTests({
    bin: 'go',
    spawnSyncImpl() {
      return { status: 0, stdout: 'ok scriptureforge/tools/zoomprobe\n', stderr: '' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /production evidence probe tests missing package result lines/);
  assert.match(result.output, /\.\/tools\/loadtest/);
});

test('runGoProbeTests propagates failing probe test output', () => {
  const result = runGoProbeTests({
    bin: 'go',
    spawnSyncImpl() {
      return { status: 1, stdout: '', stderr: 'FAIL scriptureforge/tools/zoomprobe\n' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /FAIL scriptureforge\/tools\/zoomprobe/);
});

function requiredProbePackageOutput() {
  return `${goProbePackages.map((packageName) => `ok ${packageName.replace(/^\.\//, 'scriptureforge/')} 0.001s`).join('\n')}\n`;
}
