import assert from 'node:assert/strict';
import test from 'node:test';
import { loadRustProtobufSources, validateRustProtobufSources } from './verify-rust-protobuf.mjs';

test('validateRustProtobufSources accepts repository Rust protobuf tooling', async () => {
  const result = validateRustProtobufSources(await loadRustProtobufSources());

  assert.equal(result.vendoredProtoc, true);
  assert.equal(result.ambientProtocNotRequired, true);
  assert.equal(result.generatedTypesCovered, true);
  assert.equal(result.generatedGrpcClientServerCovered, true);
  assert.equal(result.protoContractCovered, true);
  assert.equal(result.lockfilePlatformProtocCovered, true);
  assert.equal(result.healthServiceCovered, true);
  assert.equal(result.boundedVectorSearchInputs, true);
  assert.equal(result.rustRuntimeObservabilityCovered, true);
});

test('validateRustProtobufSources rejects missing vendored protoc wiring', async () => {
  const sources = await loadRustProtobufSources();
  sources.cargoToml = sources.cargoToml.replace('protoc-bin-vendored = "3"', '');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /vendor protoc/,
  );
});

test('validateRustProtobufSources rejects ambient protoc discovery', async () => {
  const sources = await loadRustProtobufSources();
  sources.buildRs = `${sources.buildRs}\nfn ambient_protoc_regression() { let _ = Command::new("protoc"); let _ = which::which("protoc"); }\n`;

  assert.throws(
    () => validateRustProtobufSources(sources),
    /ambient protoc/,
  );
});

test('validateRustProtobufSources rejects ambient PROTOC requirements', async () => {
  const sources = await loadRustProtobufSources();
  sources.buildRs = `${sources.buildRs}\nfn ambient_protoc_env_regression() -> Result<(), Box<dyn std::error::Error>> { let _ = std::env::var("PROTOC")?; Ok(()) }\n`;

  assert.throws(
    () => validateRustProtobufSources(sources),
    /ambient PROTOC/,
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

test('validateRustProtobufSources rejects tenantless vector search proto contract', async () => {
  const sources = await loadRustProtobufSources();
  sources.proto = sources.proto.replace(
    /message VectorSearchRequest\s*\{\s*string organization_id = 1;/,
    'message VectorSearchRequest {\n    string tenant_hint = 1;',
  );

  assert.throws(
    () => validateRustProtobufSources(sources),
    /bounded tenant-scoped vector-search request fields/,
  );
});

test('validateRustProtobufSources rejects changed ScriptureEngine RPC signatures', async () => {
  const sources = await loadRustProtobufSources();
  sources.proto = sources.proto.replace(
    'rpc SearchByVector (VectorSearchRequest) returns (VectorSearchResponse);',
    'rpc SearchByVector (VectorSearchRequest) returns (EmbedTextResponse);',
  );

  assert.throws(
    () => validateRustProtobufSources(sources),
    /ScriptureEngine RPC signatures/,
  );
});

test('validateRustProtobufSources rejects missing vector search protobuf coverage', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replace('generated_vector_search_response_holds_results', 'removed_vector_search_proto_test');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /vector-search response\/result types/,
  );
});

test('validateRustProtobufSources rejects missing generated gRPC client/server coverage', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replace('generated_grpc_client_and_server_types_compile', 'removed_grpc_client_server_test');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /gRPC client\/server types/,
  );
});

test('validateRustProtobufSources rejects missing bounded vector search input validation', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replaceAll('validate_vector_search_request', 'removed_vector_search_validator');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /validate vector-search requests/,
  );
});

test('validateRustProtobufSources rejects missing gRPC health service registration', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replace('.add_service(health_service)', '.add_service(/* removed health service */)');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /health service/,
  );
});

test('validateRustProtobufSources rejects localhost-only Rust defaults', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain
    .replace('unwrap_or_else(|_| "0.0.0.0:50051".to_string())', 'unwrap_or_else(|_| "127.0.0.1:50051".to_string())')
    .replace('unwrap_or_else(|_| "0.0.0.0:9102".to_string())', 'unwrap_or_else(|_| "127.0.0.1:9102".to_string())');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /0\.0\.0\.0:50051/,
  );
});

test('validateRustProtobufSources rejects incomplete vendored protoc lockfile coverage', async () => {
  const sources = await loadRustProtobufSources();
  sources.cargoLock = sources.cargoLock.replace('name = "protoc-bin-vendored-win32"', 'name = "removed-protoc-bin-vendored-win32"');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /protoc-bin-vendored-win32/,
  );
});

test('validateRustProtobufSources rejects missing non-host vendored protoc platform packages', async () => {
  const sources = await loadRustProtobufSources();
  sources.cargoLock = sources.cargoLock.replace('name = "protoc-bin-vendored-linux-s390_64"', 'name = "removed-protoc-bin-vendored-linux-s390_64"');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /protoc-bin-vendored-linux-s390_64/,
  );
});

test('validateRustProtobufSources rejects the future-incompatible SQLx lane', async () => {
  const sources = await loadRustProtobufSources();
  sources.cargoToml = sources.cargoToml.replace('version = "0.9", features = ["runtime-tokio", "tls-rustls", "postgres", "uuid"]', 'version = "0.7", features = ["runtime-tokio-rustls", "postgres", "uuid"]');
  sources.cargoLock = sources.cargoLock.replace('name = "sqlx-postgres"\nversion = "0.9.0"', 'name = "sqlx-postgres"\nversion = "0.7.4"');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /SQLx 0\.9/,
  );
});

test('validateRustProtobufSources rejects dynamic SQL query strings', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = `${sources.rustMain}\nfn bad_dynamic_query_marker() { let _ = \"sqlx::query(&query)\"; }\n`;

  assert.throws(
    () => validateRustProtobufSources(sources),
    /dynamic SQL/,
  );
});

test('validateRustProtobufSources rejects incomplete Rust metrics coverage', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replaceAll('scriptureforge_rust_engine_vector_search_failures_total', 'removed_vector_search_failure_metric');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /vector_search_failures_total/,
  );
});

test('validateRustProtobufSources rejects missing traceparent coverage', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replaceAll('traceparent_metadata_extracts_trace_id', 'removed_traceparent_test');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /traceparent extraction/,
  );
});

test('validateRustProtobufSources rejects missing deployment metadata coverage', async () => {
  const sources = await loadRustProtobufSources();
  sources.rustMain = sources.rustMain.replaceAll('SERVICE_VERSION', 'REMOVED_RELEASE_METADATA');

  assert.throws(
    () => validateRustProtobufSources(sources),
    /SERVICE_VERSION/,
  );
});
