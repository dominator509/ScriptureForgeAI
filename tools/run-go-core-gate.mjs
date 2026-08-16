import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';
import { resolve } from 'node:path';

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
  'websocket_redis_pubsub_replica_test=true',
  'abuse_rate_limit_routes_test=true',
  'abuse_auth_route_limit_test=true',
  'abuse_journal_route_limit_test=true',
  'abuse_rooms_route_limit_test=true',
  'abuse_websocket_route_limit_test=true',
  'abuse_ai_route_limit_test=true',
  'abuse_legacy_auth_alias_bucket_test=true',
  'observability_trace_id_tests_passed=true',
  'observability_metrics_endpoint_tests_passed=true',
  'observability_dependency_span_tests_passed=true',
  'observability_profile_metric_tests_passed=true',
  'zoom_resilience_tests_passed=true',
  'zoom_timeout_fallback_test=true',
  'zoom_retry_circuit_test=true',
  'zoom_webhook_signature_test=true',
  'zoom_webhook_duplicate_idempotency_test=true',
  'zoom_webhook_room_mapping_test=true',
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
  'TestRedisRoomHubsDeliverPublishedEventsAcrossReplicas',
];

export const goTestRequiredAbuseTests = [
  'TestMountedAuthRoutesEnforceAbuseRateLimit',
  'TestLegacyAuthAliasSharesCanonicalAbuseBucket',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_register_canonical',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_login_canonical',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_refresh_canonical',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_logout_canonical',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_mfa_verify_canonical',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_mfa_enroll_canonical',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_workspace_switch_canonical',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_register_legacy_alias',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/auth_login_legacy_alias',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/ai_canonical_study_generation',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/ai_legacy_curriculum_alias',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/journal_bootstrap',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/journal_list',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/journal_create',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/journal_read',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/rooms_create',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/rooms_active',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/rooms_state_polling',
  'TestMountedSensitiveRoutesEnforceConfiguredAbuseProfiles/websocket_stream',
];

export const goTestRequiredObservabilityTests = [
  'TestMiddlewareAddsTraceIDStructuredLogAndMetrics',
  'TestMiddlewareProvidesObserverForDependencyMetrics',
  'TestMiddlewarePreservesInboundTraceIDAndNormalizesIDs',
  'TestMiddlewarePropagatesW3CTraceparent',
  'TestMiddlewareBindsOTelSpanToAcceptedXTraceID',
  'TestMiddlewareFallsBackToXTraceIDWhenTraceparentInvalid',
  'TestMiddlewareRejectsInvalidXTraceIDAndGeneratorFallbacks',
  'TestMetricsHandlerServesPrometheusText',
  'TestMetricsHandlerRestrictsMethods',
  'TestMiddlewareDoesNotRecordMetricsScrapes',
  'TestMiddlewarePreservesStreamingResponseWriterCapabilities',
  'TestObserveDependencyAddsLowCardinalityMetrics',
  'TestObserveDependencyFromContextAddsTraceSpan',
  'TestMockDependencyStatusIsError',
  'TestArchitectureMetricProfilesExposeWebSocketAndAIInference',
];

export const goTestRequiredZoomTests = [
  'TestCreateMeetingFallsBackAndOpensCircuitAfterTimeouts',
  'TestCreateMeetingRetriesTransientZoomFailure',
  'TestCreateMeetingFallsBackAndOpensCircuitAfterMeetingTimeouts',
  'TestCreateMeetingUsesOfflineFallbackWhenCredentialsMissing',
  'TestCreateMeetingDoesNotUseAmbientTestModeMockWhenCredentialsMissing',
  'TestGetMeetingStatusEmitsZoomDependencyMetric',
  'TestZoomWebhookRejectsInvalidSignature',
  'TestZoomWebhookRejectsStaleSignedDelivery',
  'TestZoomWebhookMapsMeetingToRoomAndIsDuplicateSafe',
  'TestZoomWebhookConcurrentDuplicateDoesNotRepeatRoomLookup',
  'TestZoomWebhookDoesNotMutateStateWhenMeetingMappingIsMissing',
  'TestZoomWebhookDoesNotFallbackToMeetingIDWhenMappingFails',
  'TestZoomWebhookDoesNotConsumeDeliveryIDWhenMappingFails',
  'TestZoomWebhookDoesNotConsumeDeliveryIDWhenStateMutationFails',
  'TestZoomWebhookProcessesDistinctTrackedDeliveries',
  'TestZoomWebhookURLValidationReturnsEncryptedTokenWithoutStateMutation',
  'TestZoomWebhookDeliveryCacheIsBounded',
  'TestZoomWebhookEndedEventUpdatesMappedRoomInactive',
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
  const childEnv = {
    ...env,
    GOCACHE: env.GOCACHE || resolve(cwd, '.gocache'),
  };
  const child = spawnSyncImpl(command, plan.args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
    env: childEnv,
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
  const websocket = collectMissingGoTests(output, goTestRequiredWebSocketTests);
  const abuse = collectMissingGoTests(output, goTestRequiredAbuseTests);
  const observability = collectMissingGoTests(output, goTestRequiredObservabilityTests);
  const zoom = collectMissingGoTests(output, goTestRequiredZoomTests);
  const errors = [];
  if (websocket.skipped.length > 0 || websocket.missing.length > 0) {
    errors.push(`WebSocket production-behavior proof (${formatMissingDetails(websocket)})`);
  }
  if (abuse.skipped.length > 0 || abuse.missing.length > 0) {
    errors.push(`abuse/rate-limit route proof (${formatMissingDetails(abuse)})`);
  }
  if (observability.skipped.length > 0 || observability.missing.length > 0) {
    errors.push(`observability trace/metrics proof (${formatMissingDetails(observability)})`);
  }
  if (zoom.skipped.length > 0 || zoom.missing.length > 0) {
    errors.push(`Zoom resilience/webhook proof (${formatMissingDetails(zoom)})`);
  }
  if (errors.length > 0) {
    throw new Error(`go-test-gate missing required ${errors.join('; ')}`);
  }
}

function collectMissingGoTests(output, testNames) {
  const missing = [];
  const skipped = [];
  for (const testName of testNames) {
    const escaped = escapeRegExp(testName);
    if (new RegExp(`--- SKIP: ${escaped}\\b`).test(output)) {
      skipped.push(testName);
      continue;
    }
    if (!new RegExp(`--- PASS: ${escaped}\\b`).test(output)) {
      missing.push(testName);
    }
  }
  return { missing, skipped };
}

function formatMissingDetails({ missing, skipped }) {
  return [
    skipped.length > 0 ? `skipped: ${skipped.join(', ')}` : '',
    missing.length > 0 ? `missing PASS lines: ${missing.join(', ')}` : '',
  ].filter(Boolean).join('; ');
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
