import { spawnSync } from 'node:child_process';

const isWindows = process.platform === 'win32';

export const defaultCargoBin = (platform = process.platform) => (platform === 'win32' ? '.\\.tools\\cargo\\bin\\cargo.exe' : './.tools/cargo/bin/cargo');

export const rustCargoRequiredTests = [
  'generated_protobuf_types_compile_and_round_trip',
  'generated_vector_search_response_holds_results',
  'generated_grpc_client_and_server_types_compile',
  'vector_search_request_rejects_unbounded_or_invalid_inputs',
  'scripture_engine_health_service_name_matches_grpc_service',
  'default_bind_address_is_reachable_outside_localhost',
  'default_metrics_address_is_reachable_outside_localhost',
  'default_observability_config_is_staging_safe',
  'traceparent_metadata_extracts_trace_id',
  'malformed_traceparent_does_not_emit_trace_id',
  'rust_engine_metrics_render_prometheus_counters',
  'metrics_http_response_allows_get_and_head_only',
  'json_escape_handles_control_characters',
];

export const rustCargoProofMarkers = [
  'rust_cargo_locked_test=true',
  'rust_cargo_ambient_protoc_poisoned=true',
  'rust_protobuf_generated_types_test=true',
  'rust_protobuf_generated_grpc_test=true',
  'rust_vector_search_bounds_test=true',
  'rust_health_service_test=true',
  'rust_bind_address_test=true',
  'rust_observability_defaults_test=true',
  'rust_traceparent_test=true',
  'rust_metrics_render_test=true',
  'rust_metrics_http_test=true',
  'rust_json_escape_test=true',
  ...rustCargoRequiredTests,
];

export function parseArgs(argv) {
  const args = {
    bin: defaultCargoBin(),
    cwd: process.cwd(),
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--bin') {
      args.bin = argv[i + 1];
      i += 1;
    } else if (argv[i]?.startsWith('--bin=')) {
      args.bin = argv[i].slice('--bin='.length);
    } else if (argv[i] === '--cwd') {
      args.cwd = argv[i + 1];
      i += 1;
    } else if (argv[i]?.startsWith('--cwd=')) {
      args.cwd = argv[i].slice('--cwd='.length);
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

export function rustCargoArgs() {
  return ['test', '--locked', '--manifest-path', 'services/scripture-engine/Cargo.toml'];
}

export function validateRustCargoOutput(output) {
  const missing = rustCargoRequiredTests.filter((testName) => !new RegExp(`test tests::${escapeRegex(testName)} \\.\\.\\. ok`).test(output));
  if (missing.length > 0) {
    throw new Error(`rust-cargo-test missing required Rust PASS lines: ${missing.join(', ')}`);
  }
  if (!/test result: ok\./.test(output)) {
    throw new Error('rust-cargo-test output missing successful cargo test summary');
  }
  const summaries = parseCargoTestSummaries(output);
  if (summaries.length === 0) {
    throw new Error('rust-cargo-test output missing parseable cargo test summary');
  }
  for (const summary of summaries) {
    if (summary.failed > 0 || summary.ignored > 0 || summary.measured > 0 || summary.filteredOut > 0) {
      throw new Error('rust-cargo-test output must not contain failed, ignored, measured, or filtered tests');
    }
  }
  const unitSummary = summaries.find((summary) => summary.passed >= rustCargoRequiredTests.length);
  if (!unitSummary) {
    throw new Error(`rust-cargo-test output missing unit-test summary with at least ${rustCargoRequiredTests.length} passed tests`);
  }
}

export function runRustCargoGate({
  bin = defaultCargoBin(),
  cwd = process.cwd(),
  spawnSyncImpl = spawnSync,
  env = process.env,
} = {}) {
  const args = rustCargoArgs();
  const cargoEnv = {
    ...env,
    PROTOC: '__scriptureforge_invalid_ambient_protoc__',
  };
  const result = spawnSyncImpl(bin, args, {
    cwd,
    env: cargoEnv,
    encoding: 'utf8',
    shell: false,
  });
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  const combined = `${stdout}\n${stderr}`;
  if (result.error) {
    return { exitCode: 1, output: result.error.message, args };
  }
  if (result.status !== 0) {
    return { exitCode: result.status ?? 1, output: combined, args };
  }
  try {
    validateRustCargoOutput(combined);
  } catch (error) {
    return {
      exitCode: 1,
      output: `${combined}\nrust-cargo-test proof validation failed: ${error.message}`,
      args,
    };
  }
  const proof = `rust-cargo-test validated: ${rustCargoProofMarkers.join(', ')}`;
  return {
    exitCode: 0,
    output: `${combined}\n${proof}`,
    proofName: 'rust-cargo-test',
    markers: rustCargoProofMarkers,
    args,
  };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parseCargoTestSummaries(output) {
  const summaries = [];
  const pattern = /test result: ok\. (?<passed>\d+) passed; (?<failed>\d+) failed; (?<ignored>\d+) ignored; (?<measured>\d+) measured; (?<filteredOut>\d+) filtered out/g;
  for (const match of output.matchAll(pattern)) {
    summaries.push({
      passed: Number(match.groups.passed),
      failed: Number(match.groups.failed),
      ignored: Number(match.groups.ignored),
      measured: Number(match.groups.measured),
      filteredOut: Number(match.groups.filteredOut),
    });
  }
  return summaries;
}

async function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const result = runRustCargoGate(args);
    if (result.output) {
      process.stdout.write(`${result.output.trimEnd()}\n`);
    }
    process.exit(result.exitCode);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-rust-cargo-gate.mjs')) {
  main();
}
