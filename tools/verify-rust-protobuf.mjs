import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const defaultFiles = {
  cargoToml: 'services/scripture-engine/Cargo.toml',
  buildRs: 'services/scripture-engine/build.rs',
  proto: 'proto/scripture.proto',
  rustMain: 'services/scripture-engine/src/main.rs',
};

export async function loadRustProtobufSources(files = defaultFiles) {
  return {
    cargoToml: await readFile(files.cargoToml, 'utf8'),
    buildRs: await readFile(files.buildRs, 'utf8'),
    proto: await readFile(files.proto, 'utf8'),
    rustMain: await readFile(files.rustMain, 'utf8'),
  };
}

export function validateRustProtobufSources(sources) {
  assert.match(sources.cargoToml, /\[build-dependencies\][\s\S]*protoc-bin-vendored\s*=\s*"3"/, 'Rust build dependencies must vendor protoc');
  assert.match(sources.cargoToml, /\[build-dependencies\][\s\S]*tonic-build\s*=\s*"0\.10"/, 'Rust build dependencies must include tonic-build');
  assert.match(sources.cargoToml, /\[dependencies\][\s\S]*tonic\s*=\s*"0\.10"/, 'Rust dependencies must include tonic');
  assert.match(sources.cargoToml, /\[dependencies\][\s\S]*prost\s*=\s*"0\.12"/, 'Rust dependencies must include prost');

  assert.ok(sources.buildRs.includes('protoc_bin_vendored::protoc_bin_path()'), 'build.rs must resolve vendored protoc');
  assert.ok(sources.buildRs.includes('std::env::set_var("PROTOC", protoc)'), 'build.rs must set PROTOC for tonic_build');
  assert.ok(sources.buildRs.includes('../../proto/scripture.proto'), 'build.rs must compile the repository scripture proto');
  assert.ok(sources.buildRs.includes('tonic_build::configure().compile'), 'build.rs must invoke tonic_build compilation');
  assert.ok(sources.buildRs.includes('cargo:rerun-if-changed'), 'build.rs must rerun when proto changes');

  assert.ok(sources.proto.includes('syntax = "proto3";'), 'scripture proto must declare proto3 syntax');
  assert.ok(sources.proto.includes('package scriptureforge.engine;'), 'scripture proto must declare the scriptureforge.engine package');
  assert.ok(sources.proto.includes('service ScriptureEngine'), 'scripture proto must define the ScriptureEngine service');
  assert.ok(sources.proto.includes('rpc ProcessTextEmbedding'), 'scripture proto must define ProcessTextEmbedding');
  assert.ok(sources.proto.includes('rpc SearchByVector'), 'scripture proto must define SearchByVector');

  assert.ok(sources.rustMain.includes('tonic::include_proto!("scriptureforge.engine")'), 'Rust service must include generated scriptureforge.engine protobuf code');
  assert.ok(sources.rustMain.includes('generated_protobuf_types_compile_and_round_trip'), 'Rust tests must instantiate generated protobuf request/response types');
  assert.ok(sources.rustMain.includes('scripture_engine_service_name'), 'Rust tests must verify the generated gRPC service name');

  return {
    vendoredProtoc: true,
    generatedTypesCovered: true,
  };
}

async function main() {
  const sources = await loadRustProtobufSources();
  const result = validateRustProtobufSources(sources);
  console.log(`Rust protobuf tooling verified: vendored_protoc=${result.vendoredProtoc}, generated_types_covered=${result.generatedTypesCovered}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('verify-rust-protobuf.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
