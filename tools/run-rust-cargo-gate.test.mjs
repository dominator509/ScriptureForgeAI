import assert from 'node:assert/strict';
import test from 'node:test';
import {
  defaultCargoBin,
  parseArgs,
  runRustCargoGate,
  rustCargoArgs,
  rustCargoProofMarkers,
  rustCargoRequiredTests,
  validateRustCargoOutput,
} from './run-rust-cargo-gate.mjs';

test('parseArgs supports bin and cwd', () => {
  const args = parseArgs(['--bin=cargo', '--cwd', 'repo']);
  assert.equal(args.bin, 'cargo');
  assert.equal(args.cwd, 'repo');
});

test('defaultCargoBin resolves repo-local Cargo by platform', () => {
  assert.equal(defaultCargoBin('win32'), '.\\.tools\\cargo\\bin\\cargo.exe');
  assert.equal(defaultCargoBin('linux'), './.tools/cargo/bin/cargo');
});

test('rustCargoArgs runs locked manifest test gate', () => {
  assert.deepEqual(rustCargoArgs(), ['test', '--locked', '--manifest-path', 'services/scripture-engine/Cargo.toml']);
});

test('validateRustCargoOutput requires protobuf and runtime PASS lines', () => {
  assert.doesNotThrow(() => validateRustCargoOutput(requiredRustPassOutput()));
  assert.throws(
    () => validateRustCargoOutput(requiredRustPassOutput().replace('test tests::generated_grpc_client_and_server_types_compile ... ok', 'test tests::generated_grpc_client_and_server_types_compile ... ignored')),
    /generated_grpc_client_and_server_types_compile/,
  );
  assert.throws(
    () => validateRustCargoOutput(requiredRustPassOutput().replace('test result: ok.', 'test result: FAILED.')),
    /successful cargo test summary/,
  );
});

test('runRustCargoGate emits proof markers after validating cargo output', () => {
  const calls = [];
  const result = runRustCargoGate({
    bin: 'cargo',
    cwd: 'repo',
    spawnSyncImpl(command, args, options) {
      calls.push({ command, args, options });
      return { status: 0, stdout: requiredRustPassOutput(), stderr: '' };
    },
    env: { CARGO_HOME: '.tools/cargo' },
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.proofName, 'rust-cargo-test');
  assert.deepEqual(result.markers, rustCargoProofMarkers);
  assert.equal(calls[0].command, 'cargo');
  assert.deepEqual(calls[0].args, rustCargoArgs());
  assert.equal(calls[0].options.env.CARGO_HOME, '.tools/cargo');
});

test('runRustCargoGate rejects successful cargo output without proof tests', () => {
  const result = runRustCargoGate({
    bin: 'cargo',
    spawnSyncImpl() {
      return { status: 0, stdout: 'test result: ok. 4 passed; 0 failed\n', stderr: '' };
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /missing required Rust PASS lines/);
});

function requiredRustPassOutput() {
  return `${rustCargoRequiredTests.map((testName) => `test tests::${testName} ... ok`).join('\n')}\ntest result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n`;
}
