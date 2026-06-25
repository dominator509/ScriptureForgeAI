import assert from 'node:assert/strict';
import test from 'node:test';
import { loadRustProtobufSources, validateRustProtobufSources } from './verify-rust-protobuf.mjs';

test('validateRustProtobufSources accepts repository Rust protobuf tooling', async () => {
  const result = validateRustProtobufSources(await loadRustProtobufSources());

  assert.equal(result.vendoredProtoc, true);
  assert.equal(result.generatedTypesCovered, true);
});

test('validateRustProtobufSources rejects missing vendored protoc wiring', async () => {
  const sources = await loadRustProtobufSources();
  sources.cargoToml = sources.cargoToml.replace('protoc-bin-vendored = "3"', '');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /vendor protoc/,
  );
});

test('validateRustProtobufSources rejects missing generated type coverage', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replace('generated_protobuf_types_compile_and_round_trip', 'removed_generated_proto_test');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /generated protobuf request\/response types/,
  );
});
