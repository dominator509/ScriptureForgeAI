import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  defaultTerraformBin,
  defaultTerraformInitArgs,
  isNetworkBlocked,
  parseArgs,
  runTerraformInit,
  terraformInitProofMarkers,
} from './run-terraform-init.mjs';

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

describe('run-terraform-init', () => {
  it('parses bin, cwd, repeated --arg, and positional Terraform args', () => {
    assert.deepEqual(parseArgs([
      '--bin',
      'terraform',
      '--cwd=.',
      '--arg',
      '-chdir=build/terraform',
      '--arg=init',
      '-backend=false',
    ]), {
      bin: 'terraform',
      cwd: '.',
      args: ['-chdir=build/terraform', 'init', '-backend=false'],
    });

    assert.deepEqual(parseArgs([
      '--bin=.tools/terraform/terraform',
      '--cwd=.',
      '--arg=-chdir=build/terraform',
      '--arg=init',
      '--arg=-backend=false',
    ]), {
      bin: '.tools/terraform/terraform',
      cwd: '.',
      args: ['-chdir=build/terraform', 'init', '-backend=false'],
    });

    assert.throws(() => parseArgs(['--wat']), /unknown argument --wat/);
  });

  it('keeps the safe local backend-disabled init default', () => {
    assert.deepEqual(defaultTerraformInitArgs(), ['-chdir=build/terraform', 'init', '-backend=false']);
    assert.equal(defaultTerraformBin('win32'), '.\\.tools\\terraform\\terraform.exe');
    assert.equal(defaultTerraformBin('linux'), './.tools/terraform/terraform');
  });

  it('runs Terraform init with default args and returns proof markers', () => {
    const { calls, spawnSyncImpl } = spawnSequence([{ status: 0, stdout: 'Terraform has been successfully initialized!', stderr: '' }]);

    const result = runTerraformInit({
      cwd: 'C:/dev/ScriptureForgeAI',
      platformName: 'linux',
      spawnSyncImpl,
    });

    assert.equal(result.exitCode, 0);
    assert.equal(result.blocked, false);
    assert.deepEqual(result.markers, terraformInitProofMarkers);
    assert.equal(calls[0].command, './.tools/terraform/terraform');
    assert.deepEqual(calls[0].args, ['-chdir=build/terraform', 'init', '-backend=false']);
    assert.equal(calls[0].options.cwd, 'C:/dev/ScriptureForgeAI');
  });

  it('uses explicit Terraform binary and args without dropping backend flags', () => {
    const { calls, spawnSyncImpl } = spawnSequence([{ status: 0, stdout: 'ok', stderr: '' }]);

    const result = runTerraformInit({
      bin: 'terraform',
      args: ['-chdir=build/terraform', 'init', '-backend=false', '-input=false'],
      spawnSyncImpl,
    });

    assert.equal(result.exitCode, 0);
    assert.equal(calls[0].command, 'terraform');
    assert.deepEqual(calls[0].args, ['-chdir=build/terraform', 'init', '-backend=false', '-input=false']);
  });

  it('classifies registry/network outages as local blockers', () => {
    assert.equal(isNetworkBlocked('Failed to query available provider packages'), true);
    assert.equal(isNetworkBlocked('Error: Invalid reference'), false);

    const { spawnSyncImpl } = spawnSequence([{
      status: 1,
      stdout: '',
      stderr: 'Could not connect to registry.terraform.io',
    }]);

    const result = runTerraformInit({ spawnSyncImpl });

    assert.equal(result.exitCode, 0);
    assert.equal(result.blocked, true);
    assert.match(result.output, /currently unable to reach registry\.terraform\.io/);
  });

  it('propagates real Terraform failures and spawn errors', () => {
    const invalidConfig = spawnSequence([{ status: 1, stdout: '', stderr: 'Error: Invalid provider configuration' }]);
    const invalidResult = runTerraformInit({ spawnSyncImpl: invalidConfig.spawnSyncImpl });

    assert.equal(invalidResult.exitCode, 1);
    assert.equal(invalidResult.blocked, false);
    assert.match(invalidResult.output, /Invalid provider configuration/);

    const spawnError = spawnSequence([{ status: null, stdout: '', stderr: '', error: new Error('ENOENT terraform') }]);
    const spawnResult = runTerraformInit({ spawnSyncImpl: spawnError.spawnSyncImpl });

    assert.equal(spawnResult.exitCode, 1);
    assert.match(spawnResult.output, /ENOENT terraform/);
  });
});
