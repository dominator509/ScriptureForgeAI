import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const defaultFiles = {
  cargoToml: 'services/scripture-engine/Cargo.toml',
  cargoLock: 'services/scripture-engine/Cargo.lock',
  buildRs: 'services/scripture-engine/build.rs',
  proto: 'proto/scripture.proto',
  rustMain: 'services/scripture-engine/src/main.rs',
};

export const rustProtobufProofMarkers = [
  'vendored_protoc=true',
  'ambient_protoc_not_required=true',
  'generated_types_covered=true',
  'generated_grpc_client_server_covered=true',
  'proto_contract_covered=true',
  'lockfile_platform_protoc_covered=true',
  'health_service_covered=true',
  'bounded_vector_search_inputs=true',
  'rust_runtime_observability_covered=true',
];

export async function loadRustProtobufSources(files = defaultFiles) {
  return {
    cargoToml: await readFile(files.cargoToml, 'utf8'),
    cargoLock: await readFile(files.cargoLock, 'utf8'),
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
  assert.match(sources.cargoToml, /\[dependencies\][\s\S]*sqlx\s*=\s*\{[^}]*version\s*=\s*"0\.9"[^}]*runtime-tokio[^}]*tls-rustls[^}]*postgres[^}]*uuid[^}]*\}/, 'Rust service must use the SQLx 0.9 runtime-tokio/tls-rustls dependency lane');
  assert.match(sources.cargoToml, /\[dependencies\][\s\S]*pgvector\s*=\s*\{[^}]*version\s*=\s*"0\.4"[^}]*sqlx[^}]*\}/, 'Rust service must use pgvector 0.4 with SQLx support');
  assert.ok(sources.cargoLock.includes('name = "protoc-bin-vendored"'), 'Rust lockfile must include protoc-bin-vendored');
  for (const packageName of [
    'protoc-bin-vendored-linux-aarch_64',
    'protoc-bin-vendored-linux-ppcle_64',
    'protoc-bin-vendored-linux-s390_64',
    'protoc-bin-vendored-linux-x86_32',
    'protoc-bin-vendored-linux-x86_64',
    'protoc-bin-vendored-macos-aarch_64',
    'protoc-bin-vendored-macos-x86_64',
    'protoc-bin-vendored-win32',
  ]) {
    assert.ok(sources.cargoLock.includes(`name = "${packageName}"`), `Rust lockfile must include ${packageName}`);
  }
  assert.ok(!sources.cargoLock.includes('name = "sqlx-postgres"\nversion = "0.7.4"'), 'Rust lockfile must not include the future-incompatible sqlx-postgres 0.7.4 lane');
  assert.ok(sources.cargoLock.includes('name = "sqlx-postgres"\nversion = "0.9.0"'), 'Rust lockfile must include sqlx-postgres 0.9.0');

  assert.ok(sources.buildRs.includes('protoc_bin_vendored::protoc_bin_path()'), 'build.rs must resolve vendored protoc');
  assert.ok(sources.buildRs.includes('std::env::set_var("PROTOC", protoc)'), 'build.rs must set PROTOC for tonic_build');
  assert.ok(!/Command::new\(\s*"protoc"\s*\)/.test(sources.buildRs), 'build.rs must not shell out to ambient protoc on PATH');
  assert.ok(!/which::which\(\s*"protoc"\s*\)/.test(sources.buildRs), 'build.rs must not discover ambient protoc on PATH');
  assert.ok(!/std::env::var\(\s*"PROTOC"\s*\)\?/.test(sources.buildRs), 'build.rs must not require ambient PROTOC before setting the vendored path');
  assert.ok(sources.buildRs.includes('../../proto/scripture.proto'), 'build.rs must compile the repository scripture proto');
  assert.ok(sources.buildRs.includes('tonic_build::configure().compile'), 'build.rs must invoke tonic_build compilation');
  assert.ok(sources.buildRs.includes('cargo:rerun-if-changed'), 'build.rs must rerun when proto changes');

  assert.ok(sources.proto.includes('syntax = "proto3";'), 'scripture proto must declare proto3 syntax');
  assert.ok(sources.proto.includes('package scriptureforge.engine;'), 'scripture proto must declare the scriptureforge.engine package');
  assert.match(sources.proto, /message\s+EmbedTextRequest\s*\{[\s\S]*string\s+organization_id\s*=\s*1;[\s\S]*string\s+book\s*=\s*2;[\s\S]*int32\s+chapter\s*=\s*3;[\s\S]*int32\s+verse\s*=\s*4;[\s\S]*string\s+text_content\s*=\s*5;[\s\S]*\}/, 'scripture proto must preserve tenant-scoped embedding request fields');
  assert.match(sources.proto, /message\s+VectorSearchRequest\s*\{[\s\S]*string\s+organization_id\s*=\s*1;[\s\S]*repeated\s+float\s+query_vector\s*=\s*2;[\s\S]*int32\s+top_k_results\s*=\s*3;[\s\S]*float\s+minimum_similarity_threshold\s*=\s*4;[\s\S]*\}/, 'scripture proto must preserve bounded tenant-scoped vector-search request fields');
  assert.match(sources.proto, /message\s+SearchResult\s*\{[\s\S]*string\s+book\s*=\s*1;[\s\S]*int32\s+chapter\s*=\s*2;[\s\S]*int32\s+verse\s*=\s*3;[\s\S]*string\s+text_content\s*=\s*4;[\s\S]*float\s+similarity_score\s*=\s*5;[\s\S]*\}/, 'scripture proto must preserve vector-search result fields used by API callers');
  assert.match(sources.proto, /service\s+ScriptureEngine\s*\{[\s\S]*rpc\s+ProcessTextEmbedding\s*\(\s*EmbedTextRequest\s*\)\s*returns\s*\(\s*EmbedTextResponse\s*\);[\s\S]*rpc\s+SearchByVector\s*\(\s*VectorSearchRequest\s*\)\s*returns\s*\(\s*VectorSearchResponse\s*\);[\s\S]*\}/, 'scripture proto must preserve the ScriptureEngine RPC signatures');

  assert.ok(sources.rustMain.includes('tonic::include_proto!("scriptureforge.engine")'), 'Rust service must include generated scriptureforge.engine protobuf code');
  assert.ok(sources.rustMain.includes('generated_protobuf_types_compile_and_round_trip'), 'Rust tests must instantiate generated protobuf request/response types');
  assert.ok(sources.rustMain.includes('generated_vector_search_response_holds_results'), 'Rust tests must instantiate generated vector-search response/result types');
  assert.ok(sources.rustMain.includes('generated_grpc_client_and_server_types_compile'), 'Rust tests must instantiate generated gRPC client/server types');
  assert.ok(sources.rustMain.includes('ScriptureEngineClient<tonic::transport::Channel>'), 'Rust tests must compile the generated gRPC client type');
  assert.ok(sources.rustMain.includes('ScriptureEngineServer<super::MyScriptureEngine>'), 'Rust tests must compile the generated gRPC server type');
  assert.ok(sources.rustMain.includes('validate_vector_search_request'), 'Rust service must validate vector-search requests before querying Postgres');
  assert.ok(sources.rustMain.includes('vector_search_request_rejects_unbounded_or_invalid_inputs'), 'Rust tests must reject invalid or unbounded vector-search requests');
  assert.ok(sources.rustMain.includes('const EMBEDDING_DIMENSION: usize = 1536'), 'Rust vector search must enforce the architecture embedding dimension');
  assert.ok(sources.rustMain.includes('const MAX_VECTOR_SEARCH_RESULTS: i32 = 100'), 'Rust vector search must bound top_k_results');
  assert.ok(sources.rustMain.includes('scripture_engine_service_name'), 'Rust tests must verify the generated gRPC service name');
  assert.ok(sources.rustMain.includes('tonic_health::server::health_reporter()'), 'Rust service must expose tonic gRPC health reporting');
  assert.ok(sources.rustMain.includes('.add_service(health_service)'), 'Rust gRPC server must register the health service');
  assert.ok(sources.rustMain.includes('set_serving::<ScriptureEngineServer<MyScriptureEngine>>()'), 'Rust health reporter must mark the ScriptureEngine service as SERVING');
  assert.ok(sources.rustMain.includes('default_bind_address_is_reachable_outside_localhost'), 'Rust tests must verify the default gRPC bind address is not localhost-only');
  assert.ok(sources.rustMain.includes('unwrap_or_else(|_| "0.0.0.0:50051".to_string())'), 'Rust service must default gRPC bind address to 0.0.0.0:50051 for Kubernetes service reachability');
  assert.ok(sources.rustMain.includes('default_metrics_address_is_reachable_outside_localhost'), 'Rust tests must verify the default metrics bind address is not localhost-only');
  assert.ok(sources.rustMain.includes('unwrap_or_else(|_| "0.0.0.0:9102".to_string())'), 'Rust service must default metrics bind address to 0.0.0.0:9102 for Prometheus scraping');
  for (const metricName of [
    'scriptureforge_rust_engine_embedding_requests_total',
    'scriptureforge_rust_engine_embedding_failures_total',
    'scriptureforge_rust_engine_vector_search_requests_total',
    'scriptureforge_rust_engine_vector_search_failures_total',
  ]) {
    assert.ok(sources.rustMain.includes(metricName), `Rust service must expose ${metricName} for Prometheus scraping`);
  }
  assert.ok(sources.rustMain.includes('rust_engine_metrics_render_prometheus_counters'), 'Rust tests must verify rendered Prometheus counters');
  assert.ok(sources.rustMain.includes('traceparent_from_request'), 'Rust service must extract W3C traceparent metadata from gRPC requests');
  assert.ok(sources.rustMain.includes('traceparent_metadata_extracts_trace_id'), 'Rust tests must verify traceparent extraction');
  assert.ok(sources.rustMain.includes('malformed_traceparent_does_not_emit_trace_id'), 'Rust tests must reject malformed traceparent metadata');
  assert.ok(sources.rustMain.includes('SERVICE_VERSION'), 'Rust service must read SERVICE_VERSION for release-bound observability');
  assert.ok(sources.rustMain.includes('DEPLOYMENT_ENVIRONMENT'), 'Rust service must read DEPLOYMENT_ENVIRONMENT for staging/production observability');
  assert.ok(sources.rustMain.includes('OTEL_EXPORTER_OTLP_ENDPOINT'), 'Rust service must read OTEL_EXPORTER_OTLP_ENDPOINT for trace export configuration');
  assert.ok(sources.rustMain.includes('default_observability_config_is_staging_safe'), 'Rust tests must pin observability default metadata');
  assert.ok(!sources.rustMain.includes('sqlx::query(&query)'), 'Rust vector search must not pass dynamic SQL strings to sqlx::query');

  return {
    vendoredProtoc: true,
    ambientProtocNotRequired: true,
    generatedTypesCovered: true,
    generatedGrpcClientServerCovered: true,
    protoContractCovered: true,
    lockfilePlatformProtocCovered: true,
    healthServiceCovered: true,
    boundedVectorSearchInputs: true,
    rustRuntimeObservabilityCovered: true,
  };
}

async function main() {
  const sources = await loadRustProtobufSources();
  const result = validateRustProtobufSources(sources);
  console.log(`Rust protobuf tooling verified: ${rustProtobufProofMarkers.join(', ')}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('verify-rust-protobuf.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
