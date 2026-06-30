import assert from 'node:assert/strict';
import test from 'node:test';
import {
  defaultTerraformBin,
  parseArgs,
  runTerraformCommand,
  terraformArgsForMode,
  terraformFmtProofMarkers,
  terraformValidateProofMarkers,
} from './run-terraform-command.mjs';

test('parseArgs supports mode, bin, and cwd', () => {
  const args = parseArgs(['--mode', 'fmt', '--bin=terraform', '--cwd', 'repo']);
  assert.equal(args.mode, 'fmt');
  assert.equal(args.bin, 'terraform');
  assert.equal(args.cwd, 'repo');
});

test('defaultTerraformBin resolves repo-local Terraform by platform', () => {
  assert.equal(defaultTerraformBin('win32'), '.\\.tools\\terraform\\terraform.exe');
  assert.equal(defaultTerraformBin('linux'), './.tools/terraform/terraform');
});

test('terraformArgsForMode defines fmt and validate gates', () => {
  assert.deepEqual(terraformArgsForMode('fmt'), {
    args: ['-chdir=build/terraform', 'fmt', '-check', '-recursive'],
    proofName: 'terraform-fmt-gate',
    markers: terraformFmtProofMarkers,
  });
  assert.deepEqual(terraformArgsForMode('validate'), {
    args: ['-chdir=build/terraform', 'validate'],
    proofName: 'terraform-validate-gate',
    markers: terraformValidateProofMarkers,
  });
  assert.throws(() => terraformArgsForMode('plan'), /unsupported Terraform gate mode/);
});

test('runTerraformCommand runs recursive fmt check with proof markers', () => {
  const calls = [];
  const result = runTerraformCommand({
    mode: 'fmt',
    bin: 'terraform',
    cwd: 'repo',
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: '', stderr: '' };
    },
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.proofName, 'terraform-fmt-gate');
  assert.deepEqual(result.markers, terraformFmtProofMarkers);
  assert.equal(calls[0].command, 'terraform');
  assert.deepEqual(calls[0].args, ['-chdir=build/terraform', 'fmt', '-check', '-recursive']);
  assert.equal(calls[0].options.cwd, 'repo');
});

test('runTerraformCommand runs validate with proof markers', () => {
  const result = runTerraformCommand({
    mode: 'validate',
    bin: 'terraform',
    spawnSyncImpl() {
      return { status: 0, stdout: 'Success! The configuration is valid.\n', stderr: '' };
    },
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.proofName, 'terraform-validate-gate');
  assert.deepEqual(result.markers, terraformValidateProofMarkers);
});

test('runTerraformCommand propagates failing Terraform output', () => {
  const result = runTerraformCommand({
    mode: 'validate',
    bin: 'terraform',
    spawnSyncImpl() {
      return { status: 1, stdout: '', stderr: 'Error: missing provider\n' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /missing provider/);
});
