import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  isNetworkBlocked,
  npmAuditProofMarkers,
  parseArgs,
  quoteShellArg,
  resolveAuditCommand,
  runNpmAudit,
} from './run-npm-audit.mjs';

function spawnSequence(results, calls = []) {
  return {
    calls,
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, options });
      const next = results.shift();
      assert.ok(next, `unexpected spawn call ${command} ${args.join(' ')}`);
      return next;
    },
  };
}

describe('run-npm-audit', () => {
  it('parses cwd, bin, and audit-level arguments', () => {
    assert.deepEqual(parseArgs(['--cwd', 'web', '--bin=npm', '--level=moderate']), {
      cwd: 'web',
      bin: 'npm',
      level: 'moderate',
    });
    assert.deepEqual(parseArgs(['--cwd=mobile', '--bin', 'npm.cmd', '--level', 'high']), {
      cwd: 'mobile',
      bin: 'npm.cmd',
      level: 'high',
    });
    assert.throws(() => parseArgs(['--unknown']), /unknown argument --unknown/);
  });

  it('resolves the Windows npm shim without changing explicit bins', () => {
    assert.equal(resolveAuditCommand({ bin: 'npm', platformName: 'win32' }), 'npm.cmd');
    assert.equal(resolveAuditCommand({ bin: 'pnpm', platformName: 'win32' }), 'pnpm');
    assert.equal(resolveAuditCommand({ bin: 'npm', platformName: 'linux' }), 'npm');
  });

  it('runs npm audit with the configured severity level and cwd', () => {
    const { calls, spawnSyncImpl } = spawnSequence([{ status: 0, stdout: '{}', stderr: '' }]);

    const result = runNpmAudit({
      cwd: 'web',
      level: 'moderate',
      bin: 'npm',
      platformName: 'linux',
      spawnSyncImpl,
    });

    assert.equal(result.exitCode, 0);
    assert.equal(result.blocked, false);
    assert.deepEqual(result.markers, npmAuditProofMarkers);
    assert.deepEqual(calls[0].args, ['audit', '--audit-level=moderate']);
    assert.equal(calls[0].options.cwd, 'web');
  });

  it('returns vulnerability audit failures as non-zero results', () => {
    const { spawnSyncImpl } = spawnSequence([{
      status: 1,
      stdout: '',
      stderr: 'found 1 high severity vulnerability',
    }]);

    const result = runNpmAudit({ level: 'high', spawnSyncImpl });

    assert.equal(result.exitCode, 1);
    assert.equal(result.blocked, false);
    assert.match(result.output, /high severity vulnerability/);
  });

  it('classifies registry/network outages as locally blocked instead of vulnerability failures', () => {
    assert.equal(isNetworkBlocked('npm error audit request to https://registry.npmjs.org failed ETIMEDOUT'), true);
    assert.equal(isNetworkBlocked('found 1 moderate severity vulnerability'), false);

    const { spawnSyncImpl } = spawnSequence([{
      status: 1,
      stdout: '',
      stderr: 'npm error audit request to https://registry.npmjs.org failed EAI_AGAIN',
    }]);

    const result = runNpmAudit({ spawnSyncImpl });

    assert.equal(result.exitCode, 0);
    assert.equal(result.blocked, true);
    assert.match(result.output, /currently unreachable/);
  });

  it('falls back through cmd.exe when Windows command shims cannot be spawned directly', () => {
    const { calls, spawnSyncImpl } = spawnSequence([
      { status: null, stdout: '', stderr: '', error: new Error('spawn EINVAL') },
      { status: 0, stdout: '{}', stderr: '' },
    ]);

    const result = runNpmAudit({
      cwd: 'mobile',
      level: 'high',
      bin: 'npm',
      platformName: 'win32',
      env: { ComSpec: 'C:\\Windows\\System32\\cmd.exe' },
      spawnSyncImpl,
    });

    assert.equal(result.exitCode, 0);
    assert.equal(calls[0].command, 'npm.cmd');
    assert.equal(calls[1].command, 'C:\\Windows\\System32\\cmd.exe');
    assert.deepEqual(calls[1].args, ['/d', '/s', '/c', 'npm.cmd audit --audit-level=high']);
    assert.equal(calls[1].options.cwd, 'mobile');
  });

  it('quotes shell args with spaces and embedded quotes for fallback commands', () => {
    assert.equal(quoteShellArg('simple=value'), 'simple=value');
    assert.equal(quoteShellArg('with space'), '"with space"');
    assert.equal(quoteShellArg('say"hi'), '"say\\"hi"');
  });
});
