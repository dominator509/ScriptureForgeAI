import assert from 'node:assert/strict';
import test from 'node:test';
import {
  clientCommandProofMarkers,
  parseArgs,
  quoteShellArg,
  resolveClientCommand,
  runClientCommand,
} from './run-client-command.mjs';

test('parseArgs supports client command proof settings', () => {
  const args = parseArgs([
    '--cwd', 'web',
    '--script', 'typecheck',
    '--proof-name', 'web-typecheck-gate',
    '--bin', 'npm',
    '--marker', 'web_typescript_no_emit=true',
    '--marker=web_runtime_types=true',
  ]);
  assert.equal(args.cwd, 'web');
  assert.equal(args.script, 'typecheck');
  assert.equal(args['proof-name'], 'web-typecheck-gate');
  assert.equal(args.bin, 'npm');
  assert.deepEqual(args.markers, ['web_typescript_no_emit=true', 'web_runtime_types=true']);
});

test('resolveClientCommand uses npm.cmd on Windows', () => {
  assert.equal(resolveClientCommand({ bin: 'npm', platformName: 'win32' }), 'npm.cmd');
  assert.equal(resolveClientCommand({ bin: 'npm', platformName: 'linux' }), 'npm');
  assert.equal(resolveClientCommand({ bin: 'pnpm', platformName: 'win32' }), 'pnpm');
});

test('runClientCommand emits configured proof markers after success', () => {
  const calls = [];
  const result = runClientCommand({
    cwd: 'web',
    script: 'build',
    markers: ['next_build=true'],
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: 'build ok\n', stderr: '' };
    },
    platformName: 'linux',
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.output, 'build ok\n');
  assert.deepEqual(result.markers, [...clientCommandProofMarkers, 'next_build=true']);
  assert.equal(calls[0].command, 'npm');
  assert.deepEqual(calls[0].args, ['run', 'build']);
  assert.equal(calls[0].options.cwd, 'web');
});

test('runClientCommand preserves failing exit codes', () => {
  const result = runClientCommand({
    script: 'typecheck',
    spawnSyncImpl() {
      return { status: 2, stdout: '', stderr: 'type errors\n' };
    },
    platformName: 'linux',
  });

  assert.equal(result.exitCode, 2);
  assert.match(result.output, /type errors/);
});

test('runClientCommand falls back through cmd for Windows command shims', () => {
  const calls = [];
  const result = runClientCommand({
    script: 'smoke',
    spawnSyncImpl(command, args) {
      calls.push({ command, args });
      if (calls.length === 1) {
        return { status: null, stdout: '', stderr: '', error: new Error('spawn EINVAL') };
      }
      return { status: 0, stdout: 'smoke ok', stderr: '' };
    },
    platformName: 'win32',
    env: { ComSpec: 'C:\\Windows\\System32\\cmd.exe' },
  });

  assert.equal(result.exitCode, 0);
  assert.equal(calls[0].command, 'npm.cmd');
  assert.equal(calls[1].command, 'C:\\Windows\\System32\\cmd.exe');
  assert.deepEqual(calls[1].args, ['/d', '/s', '/c', 'npm.cmd run smoke']);
});

test('quoteShellArg quotes values with spaces', () => {
  assert.equal(quoteShellArg('npm.cmd'), 'npm.cmd');
  assert.equal(quoteShellArg('hello world'), '"hello world"');
});
