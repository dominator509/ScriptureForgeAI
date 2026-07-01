import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

export const goTestProofMarkers = [
  'go_test_all_packages=true',
  'go_count_one=true',
  'go_timeout_90s=true',
  'go_verbose_test_names=true',
  'websocket_realtime_tests_passed=true',
  'websocket_invalid_event_guard_test=true',
  'websocket_event_type_guard_test=true',
  'websocket_reconnect_polling_test=true',
  'websocket_concurrent_sequence_test=true',
  'websocket_fanout_broadcast_test=true',
  'websocket_disconnect_cleanup_test=true',
  'websocket_drop_metric_test=true',
  'websocket_origin_guard_test=true',
  'websocket_polling_fallback_test=true',
  'repo_go_toolchain=true',
];

export const goTestRequiredWebSocketTests = [
  'TestLiveRoomRejectsInvalidEventAndBroadcastsAcceptedEvent',
  'TestLiveRoomRejectsInvalidEventTypesWithoutPersisting',
  'TestLiveRoomClosesOversizedEventWithoutPersisting',
  'TestLiveRoomReconnectReceivesFutureEventsAndPollingState',
  'TestLiveRoomFailsClosedWhenStateManagerMissing',
  'TestLiveRoomConcurrentSendersReceiveContiguousAcceptedBroadcasts',
  'TestLiveRoomFanOutDeliversEveryAcceptedEventToEverySubscriber',
  'TestLiveRoomDisconnectCleansSubscriberAndActiveConnectionMetric',
  'TestLiveRoomReportsDroppedBroadcastForLaggingSubscriber',
  'TestLiveRoomRejectsDisallowedOrigin',
  'TestRoomStateHandlerReturnsLatestEventForPollingFallback',
  'TestRoomStateHandlerRejectsNonMemberBeforePollingState',
  'TestRoomStateHandlerFailsClosedWhenStateManagerMissing',
];

export const goVetProofMarkers = [
  'go_vet_all_packages=true',
  'go_static_analysis=true',
  'repo_go_toolchain=true',
];

export function defaultGoBin(platformName = platform()) {
  return platformName === 'win32' ? '.\\.tools\\go\\bin\\go.exe' : './.tools/go/bin/go';
}

export function goArgsForMode(mode) {
  if (mode === 'test') {
    return {
      args: ['test', './...', '-count=1', '-timeout=90s', '-v'],
      proofName: 'go-test-gate',
      markers: goTestProofMarkers,
    };
  }
  if (mode === 'vet') {
    return {
      args: ['vet', './...'],
      proofName: 'go-vet-gate',
      markers: goVetProofMarkers,
    };
  }
  throw new Error(`unsupported Go gate mode ${mode || '<empty>'}`);
}

export function runGoCoreGate({
  mode,
  bin,
  cwd = process.cwd(),
  spawnSyncImpl = spawnSync,
  platformName = platform(),
  env = process.env,
} = {}) {
  const command = bin || defaultGoBin(platformName);
  const plan = goArgsForMode(mode);
  const child = spawnSyncImpl(command, plan.args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
    env,
  });
  const output = `${child.stdout || ''}${child.stderr || ''}${child.error ? child.error.message : ''}`;
  if ((child.status ?? 1) === 0 && mode === 'test') {
    try {
      validateGoTestOutput(output);
    } catch (error) {
      const suffix = output.endsWith('\n') || output.length === 0 ? '' : '\n';
      return {
        exitCode: 1,
        output: `${output}${suffix}${error.message}\n`,
        command,
        args: plan.args,
        proofName: plan.proofName,
        markers: plan.markers,
      };
    }
  }
  return {
    exitCode: child.status ?? 1,
    output,
    command,
    args: plan.args,
    proofName: plan.proofName,
    markers: plan.markers,
  };
}

export function validateGoTestOutput(output) {
  const missing = [];
  const skipped = [];
  for (const testName of goTestRequiredWebSocketTests) {
    const escaped = escapeRegExp(testName);
    if (new RegExp(`--- SKIP: ${escaped}\\b`).test(output)) {
      skipped.push(testName);
      continue;
    }
    if (!new RegExp(`--- PASS: ${escaped}\\b`).test(output)) {
      missing.push(testName);
    }
  }
  if (skipped.length > 0 || missing.length > 0) {
    const details = [
      skipped.length > 0 ? `skipped: ${skipped.join(', ')}` : '',
      missing.length > 0 ? `missing PASS lines: ${missing.join(', ')}` : '',
    ].filter(Boolean).join('; ');
    throw new Error(`go-test-gate missing required WebSocket production-behavior proof (${details})`);
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function parseArgs(rawArgs) {
  const parsed = {};
  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg === '--mode' || arg === '--bin' || arg === '--cwd') {
      parsed[arg.slice(2)] = rawArgs[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith('--mode=')) {
      parsed.mode = arg.slice('--mode='.length);
      continue;
    }
    if (arg.startsWith('--bin=')) {
      parsed.bin = arg.slice('--bin='.length);
      continue;
    }
    if (arg.startsWith('--cwd=')) {
      parsed.cwd = arg.slice('--cwd='.length);
      continue;
    }
    throw new Error(`unknown argument ${arg}`);
  }
  return parsed;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = runGoCoreGate({
    mode: args.mode,
    bin: args.bin,
    cwd: args.cwd || process.cwd(),
  });
  if (result.output) {
    const stream = result.exitCode === 0 ? process.stdout : process.stderr;
    stream.write(result.output.endsWith('\n') ? result.output : `${result.output}\n`);
  }
  if (result.exitCode === 0) {
    console.log(`${result.proofName} validated: ${result.markers.join(', ')}`);
    process.exit(0);
  }
  process.exit(result.exitCode);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-go-core-gate.mjs')) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
