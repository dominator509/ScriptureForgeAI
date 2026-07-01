import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { ciReleaseEvidenceProofMarkers } from './write-ci-release-evidence.mjs';

export const requiredIds = [
  'SRC-CI-001',
  'DEPLOY-TF-001',
  'DEPLOY-TLS-001',
  'DEPLOY-K8S-001',
  'SEC-SECRETS-001',
  'SEC-DBUSER-001',
  'ABUSE-LIMIT-001',
  'DATA-RLS-001',
  'DATA-REDIS-001',
  'RUST-GRPC-001',
  'OBS-OTEL-001',
  'OBS-ALERT-001',
  'CLIENT-WEB-001',
  'CLIENT-MOBILE-001',
  'EXT-ZOOM-001',
  'EXT-AI-001',
  'PERF-HTTP-001',
  'PERF-WS-001',
  'DR-ROLLBACK-001',
  'DR-BACKUP-001',
  'SEC-SIGNOFF-001',
];

export const stagingEvidenceProofMarkers = [
  'required_evidence_ids_checked=true',
  'status_values_checked=true',
  'evidence_chronology_checked=true',
  'accepted_risk_metadata_checked=true',
  'strict_release_environment_checked=true',
  'strict_probe_artifact_hosts_checked=true',
  'reserved_placeholder_hosts_rejected=true',
  'strict_release_candidate_markers_checked=true',
  'strict_service_version_release_binding_checked=true',
  'strict_segment_markers_checked=true',
  'strict_numeric_thresholds_checked=true',
  'local_mock_placeholder_markers_rejected=true',
];

const allowedStatuses = new Set([
  'pending_external',
  'passed',
  'failed',
  'blocked',
  'accepted_risk',
]);

const strictAcceptedRiskRefs = {
  'SEC-SIGNOFF-001': 'security/dependency_risk_register.md#DRR-001',
};

const strictReleaseEnvironments = new Set(['staging', 'production', 'prod']);
const terraformApprovalChangeTicketPattern = /\bchange_ticket=[a-z][a-z0-9]+-\d+\b/i;
const kubernetesWorkloadImageDigestPatterns = new Map([
  ['scriptureforge-api', /(?:scriptureforge-api|scriptureforge\/api)[^\s,;]*@sha256:[a-f0-9]{64}\b/i],
  ['scriptureforge-web', /(?:scriptureforge-web|scriptureforge\/web)[^\s,;]*@sha256:[a-f0-9]{64}\b/i],
  ['scriptureforge-rust-engine', /(?:scriptureforge-rust-engine|scriptureforge\/rust-engine)[^\s,;]*@sha256:[a-f0-9]{64}\b/i],
]);
const zoomMeetingJoinURLPattern = /zoom-meeting-create-or-fallback(?=[^;]*staging artifact)(?=[^;]*meeting)(?=[^;]*join_url)(?=[^;]*zoom\.us)/i;
const zoomMeetingOfflineFallbackPattern = /zoom-meeting-create-or-fallback(?=[^;]*staging artifact)(?=[^;]*offline:\/\/in-person)(?=[^;]*fallback)(?=[^;]*zoom)/i;
const zoomSegmentMarkerRequirements = new Map([
  ['zoom-oauth-readiness', ['staging artifact', 'oauth', 'account_credentials', 'status', 'ok', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['zoom-meeting-create-or-fallback', ['staging artifact', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['zoom-timeout-circuit-fallback', ['staging artifact', 'timeout', 'provider timeout', 'circuit', 'open', 'circuit_open_fallback', 'fallback', 'offline://in-person', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['zoom-webhook-signature-delivery', ['staging artifact', 'webhook', 'signature', 'x-zm-signature=', 'x-zm-request-timestamp=', 'stale', 'replay', '401', 'invalid', 'signed', '200', 'stale_rejected=true', 'replay_rejected=true', 'invalid_signature_rejected=true', 'signed_delivery_accepted=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['zoom-webhook-url-validation', ['staging artifact', 'endpoint.url_validation', 'plain_token=', 'encrypted_token=', 'validation_response=200', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['zoom-duplicate-webhook-idempotency', ['staging artifact', 'duplicate', 'x-zm-trackingid=', 'delivery_id=', 'delivery id', 'same Zoom event', 'idempotent', '200', 'single state mutation', 'no duplicate side effects', 'single_state_mutation=true', 'no_duplicate_side_effects=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['zoom-meeting-room-mapping', ['staging artifact', 'meeting_external_id=', 'live_rooms', 'internal_room_id=', 'redis room state', 'mapped', 'unknown meeting ignored', 'no external meeting id fallback', 'distinct_zoom_artifacts=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
]);
const aiCitationVerificationPattern = /ai-citation-verification(?=[^;]*staging artifact)(?=[^;]*no-citation rejected)(?=[^;]*hallucinated citation rejected)(?=[^;]*verified citation accepted)(?=[^;]*citation_trails)(?=[^;]*citation_id=)/i;
const aiAuditPersistencePattern = /ai-audit-persistence(?=[^;]*staging artifact)(?=[^;]*ai_request_logs)(?=[^;]*citation_trails)(?=[^;]*organization_id=)(?=[^;]*user_id=)(?=[^;]*request_id=)(?=[^;]*citation_id=)(?=[^;]*tenant rls)(?=[^;]*cross-tenant hidden)/i;
const aiRequestIDPattern = /\brequest_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const aiCitationIDPattern = /\bcitation_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const aiOrganizationIDPattern = /\borganization_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const aiUserIDPattern = /\buser_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const aiProviderValuePattern = /\bAI_PROVIDER=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/;
const aiModelValuePattern = /\bAI_CHAT_MODEL=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b/;
const aiEndpointValuePattern = /\bAI_CHAT_ENDPOINT=(https:\/\/\S+)\b/;
const aiHTTPTimeoutMSValuePattern = /\bAI_HTTP_TIMEOUT_MS=([1-9][0-9]*)\b/;
const aiMaxRetriesValuePattern = /\bAI_MAX_RETRIES=([0-9]+)\b/;
const aiProviderTimeoutPattern = /\bprovider_timeout=true\b/i;
const aiRetryExhaustedPattern = /\bretry_exhausted=true\b/i;
const aiFailClosedPattern = /\bfail_closed=true\b/i;
const zoomWebhookSignaturePattern = /\bx-zm-signature=(v0[:=][0-9a-f]{64})\b/i;
const zoomWebhookTimestampPattern = /\bx-zm-request-timestamp=([0-9]{10,})\b/i;
const zoomStaleRejectedPattern = /\bstale_rejected=true\b/i;
const zoomReplayRejectedPattern = /\breplay_rejected=true\b/i;
const zoomInvalidSignatureRejectedPattern = /\binvalid_signature_rejected=true\b/i;
const zoomSignedDeliveryAcceptedPattern = /\bsigned_delivery_accepted=true\b/i;
const zoomPlainTokenPattern = /\bplain_token=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const zoomEncryptedTokenPattern = /\bencrypted_token=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const zoomValidationResponsePattern = /\bvalidation_response=200\b/i;
const zoomMeetingExternalIDPattern = /\bmeeting_external_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const zoomInternalRoomIDPattern = /\binternal_room_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const zoomTrackingIDPattern = /\bx-zm-trackingid=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const zoomDeliveryIDPattern = /\bdelivery_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const zoomSingleStateMutationPattern = /\bsingle_state_mutation=true\b/i;
const zoomNoDuplicateSideEffectsPattern = /\bno_duplicate_side_effects=true\b/i;
const zoomProviderTimeoutPattern = /\bprovider_timeout=true\b/i;
const zoomCircuitOpenPattern = /\bcircuit_open=true\b/i;
const zoomOfflineFallbackPattern = /\boffline_fallback=true\b/i;
const mobilePlatformsPattern = /\bplatforms=([A-Za-z0-9_,.-]*android[A-Za-z0-9_,.-]*ios[A-Za-z0-9_,.-]*|[A-Za-z0-9_,.-]*ios[A-Za-z0-9_,.-]*android[A-Za-z0-9_,.-]*)\b/i;
const mobileReleaseChannelPattern = /\brelease_channel=staging\b/i;
const mobileExpoProfilePattern = /\bexpo_profile=staging\b/i;
const mobileAPIBaseURLPattern = /\bEXPO_PUBLIC_API_BASE_URL=(https:\/\/\S+)\b/i;
const mobileWSBaseURLPattern = /\bEXPO_PUBLIC_WS_BASE_URL=(wss:\/\/\S+)\b/i;
const mobileRequireNativeCryptoPattern = /\bEXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true\b/i;
const mobileDeploymentEnvironmentPattern = /\bEXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging\b/i;
const mobileNativeProviderPattern = /\bprovider=([A-Za-z0-9_.:-]+)\b/i;
const mobileNativeRequiredPattern = /\bnative_required=(true|false)\b/i;
const mobileKeyDisposedPattern = /\bkey_disposed=true\b/i;
const mobileDisposedHandleRejectedPattern = /\bdisposed_handle_rejected=true\b/i;
const mobileRevokedKeyRejectedPattern = /\brevoked_key_rejected=true\b/i;
const mobilePassphraseZeroizedPattern = /\bpassphrase_buffer_zeroized=true\b/i;
const mobileSaltZeroizedPattern = /\bsalt_buffer_zeroized=true\b/i;
const mobilePlaintextZeroizedPattern = /\bplaintext_buffer_zeroized=true\b/i;
const mobileBuildIDPattern = /\bmobile_build_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const mobileAssociatedDataSaltIDPattern = /\bassociated_data_salt_id=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b/i;
const mobileAssociatedDataVersionPattern = /\bassociated_data_salt_version=([1-9][0-9]*)\b/i;
const tlsCertHostnamePattern = /\bcert_hostname=([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9.-]+)\b/i;
const tlsCertIssuerPattern = /\bcert_issuer=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const webSmokeUserIDPattern = /\buser_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const webSmokeOrganizationIDPattern = /\borganization_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const webSmokeJournalIDPattern = /\bjournal_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const webSmokeRoomIDPattern = /\broom_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const tenantOwnerOrgIDPattern = /\bapp\.current_org_id=([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b/i;
const tenantBlockedOrgIDPattern = /\bblocked_org_id=([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b/i;
const tenantJournalIDPattern = /\bjournal_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const tenantRoomIDPattern = /\broom_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const aiSegmentMarkerRequirements = new Map([
  ['ai-provider-config', ['staging artifact', 'AI_PROVIDER', 'AI_CHAT_MODEL', 'AI_CHAT_ENDPOINT', 'AI_HTTP_TIMEOUT_MS', 'AI_MAX_RETRIES', 'OPENAI_API_KEY redacted', 'configured', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['ai-generation-route', ['staging artifact', '/api/v1/ai/generate/study', 'authenticated', 'JWT claims', 'organization_id=', 'user_id=', 'request_id=', '200', 'generated_curriculum', '[Genesis 1:1]', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['ai-timeout-degradation', ['staging artifact', 'provider timeout', 'degradation', 'retry exhausted', '503', 'fail closed', 'AI_ORCHESTRATION_ENGINE_FAULT', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['ai-citation-verification', ['staging artifact', 'no-citation rejected', 'hallucinated citation rejected', 'verified citation accepted', 'citation_trails', 'citation_id=', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['ai-audit-persistence', ['staging artifact', 'ai_request_logs', 'citation_trails', 'organization_id=', 'user_id=', 'request_id=', 'citation_id=', 'succeeded', 'failed', 'verified', 'tenant rls', 'cross-tenant hidden', 'distinct_ai_artifacts=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
]);
const obsCollectorConfigPattern = /collector-otlp-config(?=[^;]*staging artifact)(?=[^;]*receivers)(?=[^;]*otlp)(?=[^;]*4317)(?=[^;]*4318)(?=[^;]*exporters)(?=[^;]*service)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const obsAPIMetricsPattern = /api-prometheus-metrics(?=[^;]*staging artifact)(?=[^;]*scriptureforge_http_requests_total)(?=[^;]*scriptureforge_http_request_duration_seconds_sum)(?=[^;]*scriptureforge_http_requests_total\{)(?=[^;]*status=)(?=[^;]*websocket_active_connections_count)(?=[^;]*scriptureforge_dependency_operations_total\{dependency="websocket",operation="room_broadcast",status="dropped")(?=[^;]*ai_inference_duration_seconds_sum)(?=[^;]*ai_inference_duration_seconds_count)(?=[^;]*scriptureforge_dependency_operations_total\{dependency="rust_engine",operation="vector_search",status="success")(?=[^;]*scriptureforge_dependency_operation_duration_seconds_sum\{dependency="rust_engine",operation="vector_search",status="success")(?=[^;]*api_metrics_samples_positive=true)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const obsRustMetricsPattern = /rust-prometheus-metrics(?=[^;]*staging artifact)(?=[^;]*scriptureforge_rust_engine_embedding_requests_total)(?=[^;]*scriptureforge_rust_engine_embedding_failures_total)(?=[^;]*scriptureforge_rust_engine_vector_search_requests_total)(?=[^;]*scriptureforge_rust_engine_vector_search_failures_total)(?=[^;]*rust_metrics_samples_positive=true)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const rustEmbeddingRequestsPattern = /\bembedding_requests=([1-9][0-9]*(?:\.[0-9]+)?)\b/i;
const rustVectorSearchRequestsPattern = /\bvector_search_requests=([1-9][0-9]*(?:\.[0-9]+)?)\b/i;
const apiRustVectorSearchOpsPattern = /\bapi_rust_vector_search_ops=([1-9][0-9]*(?:\.[0-9]+)?)\b/i;
const apiRustVectorSearchSecondsPattern = /\bapi_rust_vector_search_seconds=(?:0\.[0-9]*[1-9][0-9]*|[1-9][0-9]*(?:\.[0-9]+)?)\b/i;
const obsTraceSearchPattern = /trace-backend-search(?=[^;]*staging artifact)(?=[^;]*scriptureforge-api)(?=[^;]*scriptureforge-rust-engine)(?=[^;]*route=\/)(?=[^;]*method=[A-Z]+)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const obsLogCorrelationPattern = /log-backend-trace-correlation(?=[^;]*staging artifact)(?=[^;]*trace_id)(?=[^;]*scriptureforge-api)(?=[^;]*scriptureforge-rust-engine)(?=[^;]*route=\/)(?=[^;]*method=[A-Z]+)(?=[^;]*timestamp=[^\s,;]+)(?=[^;]*severity=[A-Za-z0-9_.:-]+)(?=[^;]*service_version)(?=[^;]*deployment_environment)(?=[^;]*tenant_id=[A-Za-z0-9_.:-]+)(?=[^;]*user_id=[A-Za-z0-9_.:-]+)(?=[^;]*role=[A-Za-z0-9_.:-]+)(?=[^;]*distinct_otel_artifacts=true)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const obsDashboardImportPattern = /dashboard-import(?=[^;]*staging artifact)(?=[^;]*ScriptureForge)(?=[^;]*scriptureforge_http_requests_total)(?=[^;]*scriptureforge_http_request_duration_seconds_sum)(?=[^;]*websocket_active_connections_count)(?=[^;]*room_broadcast)(?=[^;]*ai_inference_duration_seconds)(?=[^;]*scriptureforge_rust_engine_)(?=[^;]*trace_id)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const obsAlertRulesPattern = /alert-rules-loaded(?=[^;]*staging artifact)(?=[^;]*ScriptureForgeHighErrorRate)(?=[^;]*ScriptureForgeTrafficAbsent)(?=[^;]*ScriptureForgeAuthFailureSpike)(?=[^;]*ScriptureForgeAbuseLimitSpike)(?=[^;]*ScriptureForgeRouteLatencyElevated)(?=[^;]*ScriptureForgeDependencyFailures)(?=[^;]*ScriptureForgeAIInferenceLatencyElevated)(?=[^;]*ScriptureForgeJournalWriteFailures)(?=[^;]*ScriptureForgeRoomStreamFailures)(?=[^;]*ScriptureForgeRoomBroadcastDrops)(?=[^;]*ScriptureForgeRustEngineFailures)(?=[^;]*scriptureforge_http_requests_total)(?=[^;]*scriptureforge_dependency_operations_total)(?=[^;]*ai_inference_duration_seconds)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const obsAlertDeliveryPattern = /alert-delivery-status(?=[^;]*staging artifact)(?=[^;]*success)(?=[^;]*delivered)(?=[^;]*test alert)(?=[^;]*alertmanager)(?=[^;]*alertname=[A-Za-z0-9_.:-]+)(?=[^;]*receiver=[A-Za-z0-9_.:-]+)(?=[^;]*delivery_id=[A-Za-z0-9_.:-]+)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const obsRetentionPolicyPattern = /telemetry-retention-policy(?=[^;]*staging artifact)(?=[^;]*retention)(?=[^;]*30 days)(?=[^;]*trace)(?=[^;]*logs)(?=[^;]*metrics)(?=[^;]*distinct_alert_artifacts=true)(?=[^;]*release_candidate=)(?=[^;]*load_run_id=)/i;
const resilienceSnapshotIDPattern = /\bsnapshot_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const resilienceKMSKeyIDPattern = /\bkms_key_id=([A-Za-z0-9][A-Za-z0-9._:/=-]*)\b/i;
const resilienceSourceSnapshotIDPattern = /\bsource snapshot_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const resiliencePreRollbackVersionPattern = /\bpre_rollback_version=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b/i;
const resiliencePostRollbackVersionPattern = /\bpost_rollback_version=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b/i;
const resilienceRolledBackFromPattern = /\brolled_back_from=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b/i;
const resilienceRolledBackToPattern = /\brolled_back_to=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b/i;
const resilienceRTOMinutesPattern = /\brto_minutes=([0-9]+)\b/i;
const resilienceRestoreDurationMinutesPattern = /\brestore_duration_minutes=([0-9]+)\b/i;
const tenantSegmentMarkerRequirements = new Map([
  ['owner-create-encrypted-journal', ['same-tenant journal write accepted', 'encrypted journal created', 'plaintext not returned', 'plaintext-shaped journal payload denied', 'malformed encrypted envelope rejected', 'journal_id=', 'release_candidate=', 'service_version=']],
  ['blocked-journal-tenant-override-write-denied', ['cross-tenant journal write denied', 'tenant override rejected', 'release_candidate=', 'service_version=']],
  ['owner-read-created-journal', ['same-tenant journal read visible', 'created journal returned', 'journal_id=', 'release_candidate=', 'service_version=']],
  ['owner-list-contains-created-journal', ['same-tenant journal list visible', 'created journal present', 'journal_id=', 'release_candidate=', 'service_version=']],
  ['blocked-read-created-journal', ['cross-tenant journal read denied', 'created journal hidden', 'journal_id=', 'release_candidate=', 'service_version=']],
  ['blocked-list-excludes-created-journal', ['cross-tenant journal list hidden', 'created journal absent', 'journal_id=', 'release_candidate=', 'service_version=']],
  ['owner-create-room', ['same-tenant room write accepted', 'room created', 'room_id=', 'release_candidate=', 'service_version=']],
  ['blocked-room-tenant-override-write-denied', ['cross-tenant room write denied', 'tenant override rejected', 'release_candidate=', 'service_version=']],
  ['owner-active-rooms-contains-created-room', ['same-tenant room list visible', 'created room present', 'room_id=', 'release_candidate=', 'service_version=']],
  ['blocked-active-rooms-excludes-created-room', ['cross-tenant room list hidden', 'created room absent', 'room_id=', 'release_candidate=', 'service_version=']],
  ['owner-room-state', ['same-tenant room state visible', 'created room state returned', 'room_id=', 'release_candidate=', 'service_version=']],
  ['blocked-room-state-denied', ['cross-tenant room state denied', 'created room state hidden', 'room_id=', 'release_candidate=', 'service_version=']],
  ['database-rls-context-proof', [
    'staging artifact',
    'current_user=scriptureforge_app',
    'non-superuser',
    'superuser=false',
    'bypassrls=false',
    'app.current_org_id',
    'app.current_org_id=',
    "current_setting('app.current_org_id')",
    'blocked_org_id=',
    'row_security=on',
    'FORCE ROW LEVEL SECURITY',
    'rls_tables_verified=9',
    'rls_forced_tables=9',
    'rls_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails',
    'rls_policy_scope=app.current_org_id',
    'organizations',
    'users',
    'scripture_texts',
    'refresh_tokens',
    'journal_entries',
    'live_rooms',
    'room_participants',
    'ai_request_logs',
    'citation_trails',
    ...tenantTableOutcomeMarkers(),
    'same-tenant read visible',
    'cross-tenant read hidden',
    'cross-tenant write denied',
    'distinct_db_rls_artifact=true',
    'release_candidate=',
    'service_version=',
  ]],
]);

function tenantTableOutcomeMarkers() {
  return [
    'organizations',
    'users',
    'scripture_texts',
    'refresh_tokens',
    'journal_entries',
    'live_rooms',
    'room_participants',
    'ai_request_logs',
    'citation_trails',
  ].flatMap((table) => [
    `rls_table_${table}_same_visible=true`,
    `rls_table_${table}_cross_hidden=true`,
    `rls_table_${table}_write_denied=true`,
  ]);
}

const tlsSegmentMarkerRequirements = new Map([
  ['api-live', ['/live', 'HTTP 200', 'release_candidate=', 'service_version=']],
  ['api-ready', ['/ready', 'HTTP 200', 'release_candidate=', 'service_version=']],
  ['api-tls', ['TLS', 'certificate', 'cert_not_after', 'cert_hostname=', 'cert_issuer=', 'release_candidate=', 'service_version=']],
  ['api-http-redirect', ['HTTP', 'HTTPS', 'redirect', 'release_candidate=', 'service_version=']],
  ['web-root', ['web root', 'HTTP 200', 'release_candidate=', 'service_version=']],
  ['web-tls', ['TLS', 'certificate', 'cert_not_after', 'cert_hostname=', 'cert_issuer=', 'release_candidate=', 'service_version=']],
  ['web-http-redirect', ['HTTP', 'HTTPS', 'redirect', 'release_candidate=', 'service_version=']],
]);
const webClientSegmentMarkerRequirements = new Map([
  ['web-root', ['web root', 'HTTP 200']],
  ['web-tls', ['TLS', 'certificate', 'cert_not_after', 'cert_hostname=', 'cert_issuer=']],
  ['web-http-redirect', ['HTTP', 'HTTPS', 'redirect']],
  ['web-auth-browser-smoke', ['staging artifact', 'login', 'register', 'authenticated', 'https://', 'user_id=', 'organization_id=', 'distinct_web_artifacts=true', 'release_candidate=', 'service_version=']],
  ['web-journal-browser-smoke', ['staging artifact', 'journal', 'encrypted', 'save', 'load', 'plaintext absent', 'associated data', 'wrong associated data rejected', 'user_id=', 'organization_id=', 'journal_id=', 'distinct_web_artifacts=true', 'release_candidate=', 'service_version=']],
  ['web-room-browser-smoke', ['staging artifact', 'room', 'create', 'select', 'WebSocket', 'connected', 'user_id=', 'organization_id=', 'room_id=', 'distinct_web_artifacts=true', 'release_candidate=', 'service_version=']],
]);
const httpPerformanceSegmentMarkerRequirements = new Map([
  ['PERF-HTTP-001', ['profile=staging_http', 'min_rps=5000', 'max_p99_ms=200', 'production_target_rps=5000', 'production_target_p99_ms=200', 'production_min_duration_ms=60000', 'duration_ms=', 'duration_ms>=60000', 'observed_rps=', 'observed_p99_ms=', 'threshold_pass=true', 'http_replica_count=', 'dependency_postgres_p99_ms=', 'dependency_redis_p99_ms=', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['verified markers', ['http_replica_artifact_verified', 'dependency_telemetry_artifact_verified', 'dependency_latency_artifact_verified=true', 'http_distinct_artifacts=true']],
]);
const websocketPerformanceSegmentMarkerRequirements = new Map([
  ['PERF-WS-001', ['staging artifact', 'profile=staging_websocket', 'min_rps=500', 'max_p99_ms=200', 'production_target_rps=500', 'production_target_p99_ms=200', 'production_min_duration_ms=60000', 'duration_ms>=60000', 'production_min_ws_events=30000', 'observed_rps=', 'observed_p99_ms=', 'threshold_pass=true', 'release_candidate=', 'service_version=', 'load_run_id=', 'ws_origin=https://', 'ws_room_id=', 'ws_user_id=', 'ws_organization_id=', 'ws_reconnect_room_id=', 'ws_polling_room_id=', 'redis_telemetry_room_id=', 'ws_reconnect_sequence_continues=true', 'ws_authenticated=true', 'ws_expected_events=', 'ws_unique_sequences=', 'ws_min_sequence=1', 'ws_max_sequence=', 'ws_polling_latest_sequence=', 'ws_sequence_contiguous=true', 'ws_replica_count=']],
  ['verified markers', ['ws_replica_artifact_url=https://', 'ws_replica_artifact_verified', 'ws_reconnect_artifact_url=https://', 'ws_reconnect_artifact_verified', 'ws_reconnect_sequence_continues=true', 'ws_polling_artifact_url=https://', 'ws_polling_artifact_verified', 'ws_polling_artifact_latest_sequence_validated=true', 'ws_polling_artifact_latest_sequence_matches_run=true', 'redis_telemetry_artifact_url=https://', 'redis_telemetry_artifact_verified', 'ws_distinct_artifacts=true', 'room_broadcast_drops=0']],
]);
const redisPerformanceSegmentMarkerRequirements = new Map([
  ['DATA-REDIS-001', ['staging artifact', 'profile=staging_websocket', 'release_candidate=', 'service_version=', 'load_run_id=', 'ws_room_id=', 'ws_user_id=', 'ws_organization_id=', 'ws_reconnect_room_id=', 'ws_polling_room_id=', 'redis_telemetry_room_id=', 'ws_reconnect_sequence_continues=true', 'ws_sequence_contiguous=true', 'production_min_ws_events=30000', 'ws_expected_events=', 'ws_unique_sequences=', 'ws_min_sequence=1', 'ws_max_sequence=', 'ws_polling_latest_sequence=', 'redis_telemetry_artifact_url=https://']],
  ['verified markers', ['ws_polling_artifact_url=https://', 'redis_telemetry_artifact_verified', 'ws_polling_artifact_latest_sequence_validated=true', 'ws_polling_artifact_latest_sequence_matches_run=true', 'ws_distinct_artifacts=true', 'room_broadcast_drops=0']],
]);
const abuseRateLimitSegmentMarkerRequirements = new Map([
  ['auth-rate-limit', ['staging artifact', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'release_candidate=', 'service_version=']],
  ['auth-account-rate-limit', ['staging artifact', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'account-scoped login', 'account_scoped=true', 'rotating forwarded client IP', 'forwarded_client_ip_rotated=true', 'release_candidate=', 'service_version=']],
  ['auth-refresh-rate-limit', ['staging artifact', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'refresh token', 'refresh_token_scoped=true', 'release_candidate=', 'service_version=']],
  ['ai-rate-limit', ['staging artifact', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'release_candidate=', 'service_version=']],
  ['journal-rate-limit', ['staging artifact', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'release_candidate=', 'service_version=']],
  ['rooms-rate-limit', ['staging artifact', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'release_candidate=', 'service_version=']],
  ['websocket-rate-limit', ['staging artifact', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'websocket upgrade', 'websocket_upgrade=true', 'release_candidate=', 'service_version=']],
  ['config_artifact_summary', ['ABUSE_LIMIT_AUTH_REQUESTS=', 'ABUSE_LIMIT_AUTH_WINDOW_SECONDS=', 'ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=', 'ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=', 'ABUSE_LIMIT_AI_REQUESTS=', 'ABUSE_LIMIT_JOURNAL_REQUESTS=', 'ABUSE_LIMIT_ROOMS_REQUESTS=', 'ABUSE_LIMIT_WEBSOCKET_REQUESTS=', 'ABUSE_LIMIT_MAX_BUCKETS=', 'TRUST_PROXY_HEADERS=true', 'X-Forwarded-For', 'X-Real-IP', 'redacted', 'distinct_abuse_artifacts=true', 'release_candidate=', 'service_version=']],
]);
const abuseConfigAssignmentKeys = [
  'ABUSE_LIMIT_AUTH_REQUESTS',
  'ABUSE_LIMIT_AUTH_WINDOW_SECONDS',
  'ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS',
  'ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS',
  'ABUSE_LIMIT_AI_REQUESTS',
  'ABUSE_LIMIT_JOURNAL_REQUESTS',
  'ABUSE_LIMIT_ROOMS_REQUESTS',
  'ABUSE_LIMIT_WEBSOCKET_REQUESTS',
  'ABUSE_LIMIT_MAX_BUCKETS',
];
const abuseRateLimitProfileSegments = [
  'auth-rate-limit',
  'auth-account-rate-limit',
  'auth-refresh-rate-limit',
  'ai-rate-limit',
  'journal-rate-limit',
  'rooms-rate-limit',
  'websocket-rate-limit',
];
const concreteIAMRoleARNPattern = /\brole_arn=arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]+\b/i;
const securitySegmentMarkerRequirements = new Map([
  ['irsa-service-account', ['staging artifact', 'namespace=staging', 'service_account=scriptureforge-api', 'role_arn=arn:aws:iam::', 'eks.amazonaws.com/role-arn', 'scriptureforge', 'trust policy', 'sts:AssumeRoleWithWebIdentity', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['secret-provider-class', ['staging artifact', 'namespace=staging', 'service_account=scriptureforge-api', 'role_arn=arn:aws:iam::', 'SecretProviderClass', 'secrets-store.csi.k8s.io', 'provider', 'aws', 'objects', 'objectName', 'objectType', 'secretsmanager', 'objectAlias', 'jmesPath', 'secretObjects', 'type', 'Opaque', 'DATABASE_URL', 'JWT_SECRET_KEY', 'OPENAI_API_KEY', 'ZOOM_WEBHOOK_SECRET_TOKEN', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['synced-secret-metadata-redacted', ['staging artifact', 'namespace=staging', 'scriptureforge-runtime-secrets', 'type', 'Opaque', 'DATABASE_URL', 'JWT_SECRET_KEY', 'OPENAI_API_KEY', 'ZOOM_WEBHOOK_SECRET_TOKEN', 'redacted', 'stringData absent', 'managed by secrets-store.csi.k8s.io', 'ownerReferences', 'secrets-store.csi.k8s.io/managed=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['iam-secrets-policy', ['staging artifact', 'role_arn=arn:aws:iam::', 'secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret', 'arn:aws:secretsmanager:', 'scoped resource', 'no wildcard resources', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['scoped-secrets-access-test', ['staging artifact', 'namespace=staging', 'service_account=scriptureforge-api', 'role_arn=arn:aws:iam::', 'allowed', 'configured secret', 'denied', 'unscoped secret', 'AccessDenied', 'distinct_secret_artifacts=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
]);
const securityRoleARNSegments = new Set([
  'irsa-service-account',
  'secret-provider-class',
  'iam-secrets-policy',
  'scoped-secrets-access-test',
]);
const strictSecretLeakMarkers = [
  'postgres://',
  'postgresql://',
  'cg9zdgdyzxm6ly8',
  'cg9zdgdyzxnxbcdovlw',
  'sk-',
  'c2st',
  'client_secret=',
  'client_secret:',
  'webhook_secret=',
  'webhook_secret:',
  'password:',
  'stringdata:',
  '-----begin',
];
const dbUserSegmentMarkerRequirements = new Map([
  ['database-scoped-user', ['staging artifact', 'connected as', 'scriptureforge_app', 'current_user=scriptureforge_app', 'superuser=false', 'bypassrls=false', 'createrole=false', 'createdb=false', 'privileged_operation_denied=true', 'app_grants_verified=true', 'app_grant_tables=9', 'app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails', 'app_grants=SELECT,INSERT,UPDATE,DELETE', 'release_candidate=', 'service_version=', 'load_run_id=']],
]);
const dbUserPrincipalBindingPattern = /database-scoped-user(?=[^;]*connected as "?scriptureforge_app"?)(?=[^;]*current_user=scriptureforge_app)/i;
const resilienceSegmentMarkerRequirements = new Map([
  ['api-ready-before-rollback', ['staging artifact', 'ready', 'service_version', 'deployment_environment', 'pre_rollback_version', 'release_candidate=', 'load_run_id=']],
  ['rollback-rollout-artifact', ['staging artifact', 'rollout', 'undo', 'revision', 'previous_revision', 'target_revision', 'scriptureforge-api', 'successfully rolled out', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['api-ready-after-rollback', ['staging artifact', 'ready', 'service_version', 'deployment_environment', 'post_rollback_version', 'rolled_back_from', 'rolled_back_to', 'release_candidate=', 'load_run_id=']],
  ['degradation-drill-artifact', ['staging artifact', 'AI', 'Zoom', 'degradation', 'fallback', 'AI_ORCHESTRATION_ENGINE_FAULT', 'offline://in-person', 'non-AI routes healthy', 'zoom circuit open', 'ai_fault=true', 'zoom_offline_fallback=true', 'non_ai_routes_healthy=true', 'zoom_circuit_open=true', 'distinct_rollback_artifacts=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['backup-snapshot-artifact', ['staging artifact', 'snapshot', 'snapshot_id', 'available', 'encrypted', 'kms_key_id=', 'retention', 'automated backup', 'source cluster', 'rpo_minutes', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['restore-drill-artifact', ['staging artifact', 'restore', 'restore_job_id', 'available', 'staging', 'restored endpoint', 'source snapshot_id', 'checksum', 'isolated restore', 'rto_minutes', 'restore_duration_minutes', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['restored-database-smoke', ['staging artifact', 'smoke passed', 'restored database', 'tenant', 'journal', 'auth', 'RLS', 'migration version', 'no plaintext journal', 'distinct_backup_artifacts=true', 'release_candidate=', 'service_version=', 'load_run_id=']],
]);
const terraformSegmentMarkerRequirements = new Map([
  ['terraform-remote-backend-init', ['staging artifact', 'terraform', 's3', 'backend', 'bucket', 'key', 'encrypt=true', 'kms_key_id=', 'versioning=enabled', 'dynamodb_table', 'successfully initialized', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['terraform-staging-plan', ['staging artifact', 'Terraform', 'Plan:', 'aws_eks_cluster', 'aws_eks_node_group', 'aws_rds_cluster', 'aws_elasticache_replication_group', 'aws_ecr_repository', 'kubernetes_deployment', 'kubernetes_ingress_v1', 'kubernetes_horizontal_pod_autoscaler_v2', 'kubernetes_pod_disruption_budget_v1', 'kubernetes_manifest', 'aws_iam_role', 'kms_key_id', 'database_kms_key_arn', 'redis_kms_key_arn', 'release_candidate=', 'service_version=', 'load_run_id=']],
]);
const terraformApplyOrApprovalSegmentMarkerSets = [
  ['staging artifact', 'Apply complete', 'Resources:', '0 destroyed', 'release_candidate=', 'service_version=', 'load_run_id=', 'distinct_terraform_artifacts=true'],
  ['staging artifact', 'deployment approval', 'approved', 'DEPLOY-TF-001', 'change_ticket=', 'release_candidate=', 'service_version=', 'load_run_id=', 'distinct_terraform_artifacts=true'],
];
const kubernetesSegmentMarkerRequirements = new Map([
  ['kubernetes-rollout-status', ['staging artifact', 'namespace', 'staging', 'deployment', 'scriptureforge-api', 'scriptureforge-web', 'scriptureforge-rust-engine', 'successfully rolled out', 'ready', 'available', 'release_candidate=', 'service_version=', 'load_run_id=']],
  ['kubernetes-workload-resources', ['staging artifact', 'namespace', 'staging', 'deployment', 'service', 'ingress', 'hpa', 'pdb', 'ready', 'available', 'targets', 'minavailable', 'readinessProbe', 'livenessProbe', 'rollingUpdate', 'maxUnavailable=0', 'minReplicas', 'maxReplicas', 'tls', 'SecretProviderClass', 'image', 'sha256:', 'release_candidate=', 'service_version=', 'load_run_id=', 'scriptureforge-api', 'scriptureforge-web', 'scriptureforge-rust-engine', 'concrete_image_digests=3', 'workload_image_digests=3', 'distinct_kubernetes_artifacts=true']],
]);
const rustSegmentMarkerRequirements = new Map([
  ['rust-grpc-health', ['staging artifact', 'grpc health', 'scriptureforge.engine.ScriptureEngine', 'SERVING', 'release_candidate=', 'service_version=', 'deployment_environment=', 'load_run_id=']],
  ['rust-metrics', ['staging artifact', 'scriptureforge_rust_engine_embedding_requests_total', 'scriptureforge_rust_engine_embedding_failures_total', 'scriptureforge_rust_engine_vector_search_requests_total', 'scriptureforge_rust_engine_vector_search_failures_total', 'Prometheus metrics', 'rust_metrics_samples_verified=true', 'rust_embedding_requests_positive=true', 'rust_vector_search_requests_positive=true', 'release_candidate=', 'service_version=', 'deployment_environment=', 'load_run_id=']],
  ['api-rust-integration-metrics', ['staging artifact', 'Go API rust_engine vector_search success', 'scriptureforge_dependency_operations_total', 'scriptureforge_dependency_operation_duration_seconds_sum', 'api_rust_metrics_samples_verified=true', 'distinct_metrics_targets=true', 'release_candidate=', 'service_version=', 'deployment_environment=', 'load_run_id=']],
]);
const mobileSegmentMarkerRequirements = new Map([
  ['mobile-eas-or-device-run', ['staging artifact', 'eas', 'build', 'finished', 'android', 'ios', 'native device', 'installed app', 'release channel staging', 'expo profile staging', 'mobile_build_id=', 'distinct_mobile_artifacts=true', 'release_candidate=', 'service_version=']],
  ['mobile-native-crypto-smoke', ['staging artifact', 'runJournalCryptoSelfTest', 'react-native-quick-crypto', 'native provider', 'native module loaded', 'provider status react-native-quick-crypto', 'provider=react-native-quick-crypto', 'native-required true', 'native_required=true', 'mobile_build_id=', 'AES-GCM', 'round-trip', 'unique_iv=true', 'unique IV', 'tamper rejected', 'associated data', 'wrong associated data rejected', 'associated_data_salt_id=', 'associated_data_salt_version=', 'non-extractable', 'provider-bound key', 'fallback-derived key rejected', 'key disposed', 'key_disposed=true', 'disposed handle rejected', 'disposed_handle_rejected=true', 'revoked_key_rejected=true', 'stale raw key rejected', 'passphrase wiped', 'passphrase buffer zeroized', 'passphrase_buffer_zeroized=true', 'salt wiped', 'salt buffer zeroized', 'salt_buffer_zeroized=true', 'plaintext cleared', 'plaintext buffer zeroized', 'plaintext_buffer_zeroized=true', 'distinct_mobile_artifacts=true', 'release_candidate=', 'service_version=']],
  ['mobile-staging-config', ['staging artifact', 'EXPO_PUBLIC_API_BASE_URL', 'EXPO_PUBLIC_WS_BASE_URL', 'EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true', 'EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging', 'mobile_build_id=', 'https://', 'wss://', 'staging', 'distinct_mobile_artifacts=true', 'release_candidate=', 'service_version=']],
]);

const disallowedStrictEvidenceMarkers = [
  'dry-run',
  'dry run',
  'localhost',
  'local-only',
  'local only',
  'loopback',
  'private-network',
  'private network',
  'private ipv6',
  'ipv4-mapped',
  'link-local',
  'link local',
  'unspecified',
  'mock',
  'placeholder',
  'stubbed',
  'synthetic',
  'test-only',
  'test only',
  'expo_public_require_native_crypto=false',
  'expo_public_require_native_crypto = false',
  'provider=webcrypto-fallback',
  'provider status webcrypto-fallback',
  'webcrypto-fallback',
  'native_required=false',
  'native-required false',
  'expo_public_deployment_environment=development',
  'expo_public_deployment_environment=local',
  'https://api.scriptureforge.com',
  'http://api.scriptureforge.com',
  'wss://api.scriptureforge.com',
  'ws://api.scriptureforge.com',
  'signature verification disabled',
  'webhook signature disabled',
  'signature verification bypassed',
  'skip signature verification',
  'alert silenced',
  'alert muted',
  'alert inhibited',
  'notification suppressed',
  'delivery suppressed',
  'not delivered',
  'delivery failed',
  'delivery failure',
  'send failed',
  'citation verification disabled',
  'citations disabled',
  'skip citation verification',
  'audit logging disabled',
  'audit persistence disabled',
  'ai_request_logs disabled',
  'citation_trails disabled',
  'threshold failed',
  'threshold failure',
  'threshold_failures',
  'rps below threshold',
  'p99 above threshold',
  'terraform init failed',
  'terraform plan failed',
  'terraform apply failed',
  'apply failed',
  'plan failed',
  'rollout failed',
  'rollout status failed',
  'not rolled out',
  'availablereplicas: 0',
  'available replicas: 0',
  'readyreplicas: 0',
  'ready replicas: 0',
  'crashloopbackoff',
  'imagepullbackoff',
  'rollback failed',
  'rollback failure',
  'rollout undo failed',
  'undo failed',
  'degradation drill failed',
  'degradation failed',
  'backup failed',
  'backup failure',
  'snapshot failed',
  'snapshot unavailable',
  'restore failed',
  'restore failure',
  'restore unavailable',
  'smoke failed',
  'rpo exceeded',
  'rto exceeded',
];

export const strictProbeFamilies = {
  'SRC-CI-001': {
    commandIncludes: 'ciprobe',
    artifactIncludes: 'ciprobe',
    summaryIncludes: ['github-actions-release-run', 'release_candidate=', 'proof markers:', ...ciReleaseEvidenceProofMarkers],
    extraSummaryOrArtifactIncludes: 'ci-release-evidence',
  },
  'DEPLOY-TF-001': {
    commandIncludes: 'deploymentprobe',
    artifactIncludes: 'deploymentprobe',
    summaryIncludes: [
      'terraform-remote-backend-init',
      'staging artifact',
      's3',
      'bucket',
      'key',
      'encrypt=true',
      'kms_key_id=',
      'versioning=enabled',
      'dynamodb_table',
      'terraform-staging-plan',
      'Plan:',
      'aws_eks_cluster',
      'aws_eks_node_group',
      'aws_rds_cluster',
      'aws_elasticache_replication_group',
      'aws_ecr_repository',
      'kubernetes_deployment',
      'kubernetes_ingress_v1',
      'kubernetes_horizontal_pod_autoscaler_v2',
      'kubernetes_pod_disruption_budget_v1',
      'kubernetes_manifest',
      'aws_iam_role',
      'kms_key_id',
      'database_kms_key_arn',
      'redis_kms_key_arn',
      'terraform-staging-apply-or-approval',
      'release_candidate',
      'service_version',
      'distinct_terraform_artifacts=true',
    ],
  },
  'DEPLOY-TLS-001': {
    commandIncludes: 'stagingprobe',
    artifactIncludes: 'stagingprobe',
    summaryIncludes: [
      'api-live',
      '/live',
      'HTTP 200',
      'api-ready',
      '/ready',
      'api-tls',
      'TLS',
      'certificate',
      'cert_not_after',
      'cert_hostname=',
      'cert_issuer=',
      'api-http-redirect',
      'HTTP',
      'HTTPS',
      'redirect',
      'web-root',
      'web root',
      'web-tls',
      'web-http-redirect',
      'release_candidate',
      'service_version',
      'load_run_id=',
    ],
  },
  'DEPLOY-K8S-001': {
    commandIncludes: 'deploymentprobe',
    artifactIncludes: 'deploymentprobe',
    summaryIncludes: [
      'kubernetes-rollout-status',
      'staging artifact',
      'namespace',
      'staging',
      'scriptureforge-api',
      'scriptureforge-web',
      'scriptureforge-rust-engine',
      'successfully rolled out',
      'ready',
      'available',
      'kubernetes-workload-resources',
      'service',
      'ingress',
      'hpa',
      'pdb',
      'targets',
      'minavailable',
      'readinessProbe',
      'livenessProbe',
      'rollingUpdate',
      'maxUnavailable=0',
      'minReplicas',
      'maxReplicas',
      'tls',
      'SecretProviderClass',
      'image',
      'sha256:',
      'release_candidate',
      'service_version',
    ],
  },
  'SEC-SECRETS-001': {
    commandIncludes: 'securityprobe',
    artifactIncludes: 'securityprobe',
    summaryIncludes: [
      'irsa-service-account',
      'namespace=staging',
      'service_account=scriptureforge-api',
      'role_arn=arn:aws:iam::',
      'eks.amazonaws.com/role-arn',
      'scriptureforge',
      'trust policy',
      'sts:AssumeRoleWithWebIdentity',
      'secret-provider-class',
      'SecretProviderClass',
      'secrets-store.csi.k8s.io',
      'provider',
      'aws',
      'objects',
      'objectName',
      'objectType',
      'secretsmanager',
      'objectAlias',
      'jmesPath',
      'secretObjects',
      'type',
      'Opaque',
      'DATABASE_URL',
      'JWT_SECRET_KEY',
      'OPENAI_API_KEY',
      'ZOOM_WEBHOOK_SECRET_TOKEN',
      'synced-secret-metadata-redacted',
      'scriptureforge-runtime-secrets',
      'redacted',
      'stringData absent',
      'managed by secrets-store.csi.k8s.io',
      'ownerReferences',
      'secrets-store.csi.k8s.io/managed=true',
      'iam-secrets-policy',
      'secretsmanager:GetSecretValue',
      'secretsmanager:DescribeSecret',
      'arn:aws:secretsmanager:',
      'scoped resource',
      'no wildcard resources',
      'scoped-secrets-access-test',
      'allowed',
      'configured secret',
      'denied',
      'unscoped secret',
      'AccessDenied',
      'distinct_secret_artifacts=true',
      'release_candidate',
      'service_version',
    ],
  },
  'SEC-DBUSER-001': {
    commandIncludes: 'securityprobe',
    artifactIncludes: 'securityprobe',
    summaryIncludes: [
      'database-scoped-user',
      'connected as',
      'current_user=scriptureforge_app',
      'superuser=false',
      'bypassrls=false',
      'createrole=false',
      'createdb=false',
      'privileged_operation_denied=true',
      'app_grants_verified=true',
      'app_grant_tables=9',
      'app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails',
      'app_grants=SELECT,INSERT,UPDATE,DELETE',
      'release_candidate',
      'service_version',
    ],
  },
  'ABUSE-LIMIT-001': {
    commandIncludes: 'abuseprobe',
    artifactIncludes: 'abuseprobe',
    summaryIncludes: [
      'account-scoped login',
      'refresh token',
      'after',
      'attempts',
      'config_artifact_verified=true',
      'config_artifact_summary',
      'ABUSE_LIMIT_AUTH_REQUESTS',
      'ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS',
      'ABUSE_LIMIT_MAX_BUCKETS',
      'TRUST_PROXY_HEADERS',
      'X-Forwarded-For',
      'X-Real-IP',
      'redacted',
      'distinct_abuse_artifacts=true',
      'release_candidate',
      'service_version',
      'load_run_id',
    ],
    extraSummaryOrArtifactIncludes: 'websocket upgrade',
  },
  'DATA-RLS-001': {
    commandIncludes: 'tenantprobe',
    artifactIncludes: 'tenantprobe',
    summaryIncludes: [
      'owner-create-encrypted-journal',
      'same-tenant journal write accepted',
      'encrypted journal created',
      'plaintext not returned',
      'plaintext-shaped journal payload denied',
      'malformed encrypted envelope rejected',
      'journal_id=',
      'blocked-journal-tenant-override-write-denied',
      'cross-tenant journal write denied',
      'tenant override rejected',
      'owner-read-created-journal',
      'same-tenant journal read visible',
      'created journal returned',
      'journal_id=',
      'owner-list-contains-created-journal',
      'same-tenant journal list visible',
      'created journal present',
      'journal_id=',
      'blocked-read-created-journal',
      'cross-tenant journal read denied',
      'created journal hidden',
      'journal_id=',
      'blocked-list-excludes-created-journal',
      'cross-tenant journal list hidden',
      'created journal absent',
      'journal_id=',
      'owner-create-room',
      'same-tenant room write accepted',
      'room created',
      'room_id=',
      'blocked-room-tenant-override-write-denied',
      'cross-tenant room write denied',
      'owner-active-rooms-contains-created-room',
      'same-tenant room list visible',
      'created room present',
      'room_id=',
      'blocked-active-rooms-excludes-created-room',
      'cross-tenant room list hidden',
      'created room absent',
      'room_id=',
      'owner-room-state',
      'same-tenant room state visible',
      'created room state returned',
      'room_id=',
      'blocked-room-state-denied',
      'cross-tenant room state denied',
      'created room state hidden',
      'room_id=',
      'database-rls-context-proof',
      'staging artifact',
      'current_user=scriptureforge_app',
      'non-superuser',
      'app.current_org_id',
      'row_security',
      'FORCE ROW LEVEL SECURITY',
      'organizations',
      'users',
      'scripture_texts',
      'refresh_tokens',
      'journal_entries',
      'live_rooms',
      'room_participants',
      'ai_request_logs',
      'citation_trails',
      'same-tenant read visible',
      'cross-tenant read hidden',
      'cross-tenant write denied',
      'distinct_db_rls_artifact=true',
      'release_candidate=',
      'service_version=',
      'load_run_id=',
    ],
  },
  'DATA-REDIS-001': {
    commandIncludes: 'loadtest',
    artifactIncludes: 'loadtest',
    summaryIncludes: [
      'staging_websocket',
      'release_candidate',
      'service_version',
      'load_run_id',
      'ws_sequence_contiguous=true',
      'ws_expected_events',
      'ws_unique_sequences',
      'ws_min_sequence',
      'ws_max_sequence',
      'ws_polling_latest_sequence',
      'ws_polling_artifact_url=https://',
      'ws_polling_artifact_latest_sequence_validated=true',
      'ws_polling_artifact_latest_sequence_matches_run=true',
      'redis_telemetry_artifact_url=https://',
      'redis_telemetry_artifact_verified',
      'ws_distinct_artifacts=true',
      'room_broadcast_drops=0',
    ],
  },
  'RUST-GRPC-001': {
    commandIncludes: 'rustprobe',
    artifactIncludes: 'rustprobe',
    summaryIncludes: [
      'rust-grpc-health',
      'staging artifact',
      'grpc health',
      'scriptureforge.engine.ScriptureEngine',
      'SERVING',
      'rust-metrics',
      'staging artifact',
      'scriptureforge_rust_engine_embedding_requests_total',
      'scriptureforge_rust_engine_embedding_failures_total',
      'scriptureforge_rust_engine_vector_search_requests_total',
      'scriptureforge_rust_engine_vector_search_failures_total',
      'Prometheus metrics',
      'rust_metrics_samples_verified=true',
      'rust_embedding_requests_positive=true',
      'rust_vector_search_requests_positive=true',
      'api-rust-integration-metrics',
      'staging artifact',
      'Go API rust_engine vector_search success',
      'scriptureforge_dependency_operations_total',
      'scriptureforge_dependency_operation_duration_seconds_sum',
      'api_rust_metrics_samples_verified=true',
      'distinct_metrics_targets=true',
      'release_candidate',
      'service_version',
      'load_run_id=',
    ],
  },
  'OBS-OTEL-001': {
    commandIncludes: 'observabilityprobe',
    artifactIncludes: 'observabilityprobe',
    summaryIncludes: [
      'collector-otlp-config',
      'staging artifact',
      'receivers',
      'otlp',
      '4317',
      '4318',
      'exporters',
      'api-prometheus-metrics',
      'scriptureforge_http_requests_total',
      'scriptureforge_http_request_duration_seconds_sum',
      'status=',
      'websocket_active_connections_count',
      'scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped"',
      'ai_inference_duration_seconds_sum',
      'ai_inference_duration_seconds_count',
      'scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"',
      'scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"',
      'rust-prometheus-metrics',
      'scriptureforge_rust_engine_embedding_requests_total',
      'scriptureforge_rust_engine_embedding_failures_total',
      'scriptureforge_rust_engine_vector_search_requests_total',
      'scriptureforge_rust_engine_vector_search_failures_total',
      'trace-backend-search',
      'scriptureforge-api',
      'scriptureforge-rust-engine',
      'log-backend-trace-correlation',
      'trace_id',
      'release_candidate',
      'service_version',
      'load_run_id',
      'deployment_environment',
      'timestamp=',
      'severity=',
      'tenant_id=',
      'user_id=',
      'role=',
      'distinct_otel_artifacts=true',
    ],
  },
  'OBS-ALERT-001': {
    commandIncludes: 'observabilityprobe',
    artifactIncludes: 'observabilityprobe',
    summaryIncludes: [
      'dashboard-import',
      'staging artifact',
      'ScriptureForge',
      'scriptureforge_http_requests_total',
      'scriptureforge_http_request_duration_seconds_sum',
      'websocket_active_connections_count',
      'room_broadcast',
      'ai_inference_duration_seconds',
      'scriptureforge_rust_engine_',
      'trace_id',
      'alert-rules-loaded',
      'ScriptureForgeHighErrorRate',
      'ScriptureForgeTrafficAbsent',
      'ScriptureForgeAuthFailureSpike',
      'ScriptureForgeAbuseLimitSpike',
      'ScriptureForgeRouteLatencyElevated',
      'ScriptureForgeDependencyFailures',
      'ScriptureForgeAIInferenceLatencyElevated',
      'ScriptureForgeJournalWriteFailures',
      'ScriptureForgeRoomStreamFailures',
      'ScriptureForgeRoomBroadcastDrops',
      'ScriptureForgeRustEngineFailures',
      'scriptureforge_dependency_operations_total',
      'ai_inference_duration_seconds',
      'alert-delivery-status',
      'success',
      'delivered',
      'test alert',
      'alertmanager',
      'alertname=',
      'receiver=',
      'delivery_id=',
      'telemetry-retention-policy',
      'retention',
      '30 days',
      'trace',
      'logs',
      'metrics',
      'distinct_alert_artifacts=true',
      'release_candidate',
      'service_version',
      'load_run_id',
    ],
  },
  'CLIENT-WEB-001': {
    commandIncludes: 'stagingprobe',
    artifactIncludes: 'stagingprobe',
    summaryIncludes: [
      'web-root',
      'web root',
      'HTTP 200',
      'web-tls',
      'TLS',
      'certificate',
      'cert_not_after',
      'cert_hostname=',
      'cert_issuer=',
      'web-http-redirect',
      'HTTP',
      'HTTPS',
      'redirect',
      'web-auth-browser-smoke',
      'staging artifact',
      'login',
      'register',
      'authenticated',
      'https://',
      'user_id=',
      'organization_id=',
      'release_candidate=',
      'service_version=',
      'load_run_id=',
      'web-journal-browser-smoke',
      'journal',
      'encrypted',
      'save',
      'load',
      'plaintext absent',
      'associated data',
      'wrong associated data rejected',
      'journal_id=',
      'release_candidate=',
      'service_version=',
      'web-room-browser-smoke',
      'room',
      'create',
      'select',
      'WebSocket',
      'connected',
      'room_id=',
      'release_candidate=',
      'service_version=',
    ],
  },
      'CLIENT-MOBILE-001': {
    commandIncludes: 'mobileprobe',
    artifactIncludes: 'mobileprobe',
    summaryIncludes: [
      'mobile-eas-or-device-run',
      'staging artifact',
      'eas',
      'build',
      'finished',
      'android',
      'ios',
      'native device',
      'installed app',
      'release channel staging',
      'expo profile staging',
      'mobile-native-crypto-smoke',
      'react-native-quick-crypto',
      'native provider',
      'native module loaded',
      'provider status react-native-quick-crypto',
      'native-required true',
      'AES-GCM',
      'round-trip',
      'unique_iv=true',
      'unique IV',
      'tamper rejected',
      'associated data',
      'wrong associated data rejected',
      'associated_data_salt_id=',
      'associated_data_salt_version=',
      'non-extractable',
      'provider-bound key',
      'fallback-derived key rejected',
      'key disposed',
      'disposed handle rejected',
      'revoked_key_rejected=true',
      'stale raw key rejected',
      'passphrase wiped',
      'passphrase buffer zeroized',
      'salt wiped',
      'salt buffer zeroized',
      'plaintext cleared',
      'plaintext buffer zeroized',
      'mobile-staging-config',
      'EXPO_PUBLIC_API_BASE_URL',
      'EXPO_PUBLIC_WS_BASE_URL',
      'EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true',
      'EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging',
      'https://',
      'wss://',
      'staging',
      'distinct_mobile_artifacts=true',
      'load_run_id=',
    ],
  },
  'EXT-ZOOM-001': {
    commandIncludes: 'zoomprobe',
    artifactIncludes: 'zoomprobe',
    summaryIncludes: [
      'zoom-oauth-readiness',
      'staging artifact',
      'oauth',
      'account_credentials',
      'status',
      'ok',
      'zoom-meeting-create-or-fallback',
      'zoom-timeout-circuit-fallback',
      'provider timeout',
      'circuit_open_fallback',
      'offline://in-person',
      'zoom-webhook-signature-delivery',
      'x-zm-signature=',
      'x-zm-request-timestamp=',
      'stale',
      'replay',
      'invalid',
      'signed',
      'zoom-webhook-url-validation',
      'endpoint.url_validation',
      'plain_token=',
      'encrypted_token=',
      'validation_response=200',
      'zoom-duplicate-webhook-idempotency',
      'x-zm-trackingid=',
      'delivery_id=',
      'delivery id',
      'same Zoom event',
      'idempotent',
      'single state mutation',
      'no duplicate side effects',
      'zoom-meeting-room-mapping',
      'meeting_external_id=',
      'live_rooms',
      'internal_room_id=',
      'redis room state',
      'unknown meeting ignored',
      'no external meeting id fallback',
      'distinct_zoom_artifacts=true',
      'release_candidate',
      'service_version',
    ],
  },
  'EXT-AI-001': {
    commandIncludes: 'aiprobe',
    artifactIncludes: 'aiprobe',
    summaryIncludes: [
      'ai-provider-config',
      'staging artifact',
      'AI_PROVIDER',
      'AI_CHAT_MODEL',
      'AI_CHAT_ENDPOINT',
      'AI_HTTP_TIMEOUT_MS',
      'AI_MAX_RETRIES',
      'OPENAI_API_KEY redacted',
      'ai-generation-route',
      '/api/v1/ai/generate/study',
      'authenticated',
      'JWT claims',
      'organization_id',
      'user_id',
      'generated_curriculum',
      '[Genesis 1:1]',
      'ai-timeout-degradation',
      'provider timeout',
      'retry exhausted',
      'fail closed',
      'AI_ORCHESTRATION_ENGINE_FAULT',
      'ai-citation-verification',
      'no-citation rejected',
      'hallucinated citation rejected',
      'verified citation accepted',
      'citation_trails',
      'citation_id=',
      'ai-audit-persistence',
      'ai_request_logs',
      'request_id=',
      'citation_id=',
      'succeeded',
      'failed',
      'verified',
      'tenant rls',
      'cross-tenant hidden',
      'distinct_ai_artifacts=true',
      'release_candidate',
      'service_version',
    ],
  },
  'PERF-HTTP-001': {
    commandIncludes: 'loadtest',
    artifactIncludes: 'loadtest',
    summaryIncludes: [
      'staging_http',
      'min_rps',
      '5000',
      'max_p99_ms',
      '200',
      'observed_rps',
      'observed_p99_ms',
      'threshold_pass=true',
      'release_candidate',
      'service_version',
      'load_run_id',
      'http_replica_artifact_verified',
      'dependency_telemetry_artifact_verified',
      'dependency_latency_artifact_verified=true',
    ],
  },
  'PERF-WS-001': {
    commandIncludes: 'loadtest',
    artifactIncludes: 'loadtest',
    summaryIncludes: [
      'staging_websocket',
      'min_rps',
      '500',
      'max_p99_ms',
      '200',
      'observed_rps',
      'observed_p99_ms',
      'threshold_pass=true',
      'release_candidate',
      'service_version',
      'load_run_id',
      'ws_origin=https://',
      'ws_authenticated=true',
      'ws_sequence_contiguous=true',
      'ws_polling_latest_sequence',
      'ws_replica_artifact_url=https://',
      'ws_replica_artifact_verified',
      'ws_reconnect_artifact_url=https://',
      'ws_reconnect_artifact_verified',
      'ws_reconnect_sequence_continues=true',
      'ws_polling_artifact_url=https://',
      'ws_polling_artifact_verified',
      'ws_polling_artifact_latest_sequence_validated=true',
      'ws_polling_artifact_latest_sequence_matches_run=true',
      'redis_telemetry_artifact_url=https://',
      'redis_telemetry_artifact_verified',
      'ws_distinct_artifacts=true',
      'room_broadcast_drops=0',
    ],
  },
  'DR-ROLLBACK-001': {
    commandIncludes: 'resilienceprobe',
    artifactIncludes: 'resilienceprobe',
    summaryIncludes: [
      'api-ready-before-rollback',
      'staging artifact',
      'ready',
      'service_version',
      'deployment_environment',
      'pre_rollback_version',
      'release_candidate',
      'rollback-rollout-artifact',
      'rollout',
      'undo',
      'revision',
      'previous_revision',
      'target_revision',
      'scriptureforge-api',
      'successfully rolled out',
      'api-ready-after-rollback',
      'post_rollback_version',
      'rolled_back_from',
      'rolled_back_to',
      'degradation-drill-artifact',
      'AI',
      'Zoom',
      'degradation',
      'fallback',
      'AI_ORCHESTRATION_ENGINE_FAULT',
      'offline://in-person',
      'non-AI routes healthy',
      'zoom circuit open',
      'ai_fault=true',
      'zoom_offline_fallback=true',
      'non_ai_routes_healthy=true',
      'zoom_circuit_open=true',
      'distinct_rollback_artifacts=true',
      'service_version',
    ],
  },
  'DR-BACKUP-001': {
    commandIncludes: 'resilienceprobe',
    artifactIncludes: 'resilienceprobe',
    summaryIncludes: [
      'backup-snapshot-artifact',
      'staging artifact',
      'snapshot',
      'snapshot_id',
      'available',
      'encrypted',
      'kms_key_id=',
      'retention',
      'automated backup',
      'source cluster',
      'rpo_minutes',
      'release_candidate',
      'service_version',
      'restore-drill-artifact',
      'restore',
      'restore_job_id',
      'staging',
      'restored endpoint',
      'source snapshot_id',
      'checksum',
      'isolated restore',
      'rto_minutes',
      'restore_duration_minutes',
      'release_candidate',
      'service_version',
      'restored-database-smoke',
      'smoke passed',
      'restored database',
      'tenant',
      'journal',
      'auth',
      'RLS',
      'migration version',
      'no plaintext journal',
      'distinct_backup_artifacts=true',
      'release_candidate',
      'service_version',
    ],
  },
};

const requiredSignoffSummaryMarkers = [
  'threat model approval',
  'security/dependency_risk_register.md#DRR-001',
  'dependency risk decision',
  'residual risk review',
  'owner/security approval',
  'release risk signoff',
  'signoff_artifact_verified=true',
  'release_candidate=',
];

export function parseArgs(argv) {
  const args = {
    evidenceFile: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.example.json',
    strictRelease: process.env.STAGING_EVIDENCE_STRICT_RELEASE === 'true',
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--manifest') {
      args.evidenceFile = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--strict-release') {
      args.strictRelease = true;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

export function validateManifest(manifest, { strictRelease = false, today = new Date().toISOString().slice(0, 10) } = {}) {
  assert.equal(manifest.schema_version, 1, 'staging evidence schema_version must be 1');
  assert.equal(typeof manifest.environment, 'string', 'environment is required');
  assert.ok(manifest.environment.length > 0, 'environment must not be empty');
  assert.equal(typeof manifest.release_candidate, 'string', 'release_candidate is required');
  assert.ok(manifest.release_candidate.length > 0, 'release_candidate must not be empty');
  assert.match(manifest.generated_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'generated_at must be an ISO UTC timestamp without milliseconds');
  assert.match(today, /^\d{4}-\d{2}-\d{2}$/, 'today must be YYYY-MM-DD');
  assert.ok(
    manifest.generated_at.slice(0, 10) <= today,
    'staging evidence generated_at must not be after validation date',
  );
  assert.ok(Array.isArray(manifest.items), 'items must be an array');

  const itemsById = new Map();
  for (const item of manifest.items) {
    assert.equal(typeof item.id, 'string', 'item id is required');
    assert.ok(!itemsById.has(item.id), `duplicate evidence item ${item.id}`);
    itemsById.set(item.id, item);
  }

  for (const id of requiredIds) {
    assert.ok(itemsById.has(id), `staging evidence manifest missing ${id}`);
  }

  for (const item of manifest.items) {
    validateItem(item, manifest.generated_at, today);
  }

  if (strictRelease) {
    validateStrictRelease(manifest);
  }

  return {
    items: manifest.items.length,
    strictRelease,
  };
}

function validateItem(item, manifestGeneratedAt, today) {
  assert.equal(typeof item.category, 'string', `${item.id} category is required`);
  assert.ok(item.category.length > 0, `${item.id} category must not be empty`);
  assert.ok(allowedStatuses.has(item.status), `${item.id} has invalid status ${item.status}`);
  assert.equal(typeof item.description, 'string', `${item.id} description is required`);
  assert.ok(item.description.length > 0, `${item.id} description must not be empty`);

  if (item.status === 'pending_external') {
    assert.ok(Array.isArray(item.required_evidence), `${item.id} pending item must list required_evidence`);
    assert.ok(item.required_evidence.length > 0, `${item.id} pending item must have at least one required evidence entry`);
    if (item.id === 'SEC-SIGNOFF-001') {
      const requiredText = item.required_evidence.join('\n');
      assert.match(
        requiredText,
        /content-verified repo security\/\*\.md signoff\/approval document or HTTPS non-local approval artifact/,
        'SEC-SIGNOFF-001 pending required_evidence must require a content-verified signoff artifact',
      );
      assert.ok(
        requiredText.includes('signoff_artifact_verified=true'),
        'SEC-SIGNOFF-001 pending required_evidence must include signoff_artifact_verified=true',
      );
    }
  }

  if (item.status === 'passed') {
    assert.ok(Array.isArray(item.evidence), `${item.id} passed item must include evidence artifacts`);
    assert.ok(item.evidence.length > 0, `${item.id} passed item must have at least one evidence artifact`);
    for (const artifact of item.evidence) {
      assert.equal(typeof artifact.observed_at, 'string', `${item.id} evidence observed_at is required`);
      assert.match(artifact.observed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, `${item.id} evidence observed_at must be ISO UTC without milliseconds`);
      assert.ok(
        artifact.observed_at <= manifestGeneratedAt,
        `${item.id} evidence observed_at must not be after manifest generated_at`,
      );
      assert.equal(typeof artifact.command_or_probe, 'string', `${item.id} evidence command_or_probe is required`);
      assert.equal(typeof artifact.artifact, 'string', `${item.id} evidence artifact path or URL is required`);
      assert.equal(typeof artifact.result_summary, 'string', `${item.id} evidence result_summary is required`);
    }
  }

  if (item.status === 'failed' || item.status === 'blocked') {
    assert.equal(typeof item.blocker, 'string', `${item.id} ${item.status} item must explain blocker`);
    assert.ok(item.blocker.length > 0, `${item.id} blocker must not be empty`);
    assert.equal(typeof item.owner, 'string', `${item.id} ${item.status} item must name an owner`);
    assert.ok(item.owner.length > 0, `${item.id} owner must not be empty`);
  }

  if (item.status === 'accepted_risk') {
    assert.equal(typeof item.decision_ref, 'string', `${item.id} accepted risk must reference a decision record`);
    assert.ok(item.decision_ref.length > 0, `${item.id} decision_ref must not be empty`);
    assert.equal(typeof item.owner, 'string', `${item.id} accepted risk must name an owner`);
    assert.ok(item.owner.length > 0, `${item.id} accepted risk owner must not be empty`);
    assert.equal(typeof item.accepted_by, 'string', `${item.id} accepted risk must name who accepted it`);
    assert.ok(item.accepted_by.length > 0, `${item.id} accepted_by must not be empty`);
    assert.match(item.review_due_at, /^\d{4}-\d{2}-\d{2}$/, `${item.id} accepted risk review_due_at must be YYYY-MM-DD`);
    assert.match(item.expires_at, /^\d{4}-\d{2}-\d{2}$/, `${item.id} accepted risk expires_at must be YYYY-MM-DD`);
    assert.match(today, /^\d{4}-\d{2}-\d{2}$/, 'today must be YYYY-MM-DD');
    assert.ok(
      item.review_due_at <= item.expires_at,
      `${item.id} accepted risk review_due_at must be on or before expires_at`,
    );
    assert.ok(
      item.expires_at >= manifestGeneratedAt.slice(0, 10),
      `${item.id} accepted risk expires_at must not be before manifest generated_at`,
    );
    assert.ok(
      item.expires_at >= today,
      `${item.id} accepted risk expires_at must not be before validation date`,
    );
    assert.ok(
      item.review_due_at >= today,
      `${item.id} accepted risk review_due_at must not be before validation date`,
    );
  }
}

function validateStrictRelease(manifest) {
  assert.ok(!manifest.release_candidate.toLowerCase().includes('replace-with'), 'strict release manifest must use a real release_candidate');
  assert.match(
    manifest.release_candidate,
    /^[0-9a-f]{40}$/i,
    'strict release manifest release_candidate must be a 40-character git commit SHA',
  );
  assert.ok(
    strictReleaseEnvironments.has(manifest.environment.toLowerCase()),
    `strict release manifest environment must be staging, production, or prod; got ${manifest.environment}`,
  );
  for (const item of manifest.items) {
    if (item.id === 'SEC-SIGNOFF-001' && item.status === 'accepted_risk') {
      validateStrictAcceptedRisk(item);
      continue;
    }
    assert.equal(item.status, 'passed', `${item.id} must be passed for strict release validation`);
    validateStrictReleaseItemEvidence(item, manifest);
  }
  assertStrictPerformanceLoadRunLinkage(manifest);
  assertStrictReleaseLoadRunLinkage(manifest);
}

function assertStrictPerformanceLoadRunLinkage(manifest) {
  const loadRunIDs = new Set();
  for (const itemID of ['PERF-HTTP-001', 'PERF-WS-001', 'DATA-REDIS-001']) {
    const item = manifest.items.find((candidate) => candidate.id === itemID);
    assert.ok(item, `strict release manifest missing ${itemID}`);
    const evidence = Array.isArray(item.evidence) ? item.evidence : [];
    const itemLoadRunIDs = new Set();
    for (const artifact of evidence) {
      const match = String(artifact.result_summary ?? '').match(/\bload_run_id=([^\s,;]+)/i);
      if (match) {
        itemLoadRunIDs.add(match[1]);
        loadRunIDs.add(match[1]);
      }
    }
    assert.equal(itemLoadRunIDs.size, 1, `${itemID} strict release evidence must include exactly one load_run_id`);
  }
  assert.equal(
    loadRunIDs.size,
    1,
    'strict release performance evidence load_run_id values must match across PERF-HTTP-001, PERF-WS-001, and DATA-REDIS-001',
  );
}

function assertStrictReleaseLoadRunLinkage(manifest) {
  const loadRunIDs = new Set();
  for (const item of manifest.items) {
    if (item.id === 'SRC-CI-001' || item.id === 'SEC-SIGNOFF-001') {
      continue;
    }
    const evidence = Array.isArray(item.evidence) ? item.evidence : [];
    for (const artifact of evidence) {
      const match = String(artifact.result_summary ?? '').match(/\bload_run_id=([^\s,;]+)/i);
      if (match) {
        loadRunIDs.add(match[1]);
      }
    }
  }
  assert.equal(
    loadRunIDs.size,
    1,
    'strict release evidence load_run_id values must match across all staging evidence items',
  );
}

function validateStrictAcceptedRisk(item) {
  assert.equal(
    item.decision_ref,
    strictAcceptedRiskRefs[item.id],
    `${item.id} accepted risk must reference ${strictAcceptedRiskRefs[item.id]}`,
  );
}

function validateStrictReleaseItemEvidence(item, manifest) {
  if (item.id === 'SEC-SIGNOFF-001') {
    validateStrictSignoffEvidence(item, manifest);
    return;
  }
  const requirement = strictProbeFamilies[item.id];
  if (!requirement) {
    return;
  }
  const evidence = Array.isArray(item.evidence) ? item.evidence : [];
  if (item.id === 'OBS-ALERT-001') {
    for (const artifact of evidence) {
      const combined = [
        artifact.command_or_probe,
        artifact.artifact,
        artifact.result_summary,
      ].map((value) => String(value ?? '').toLowerCase()).join(' ');
      assert.ok(
        !hasDisallowedStrictEvidenceMarker(combined),
        `${item.id} evidence contains forbidden non-production marker`,
      );
    }
  }
  const hasRequiredProbeReport = evidence.some((artifact) => {
    const command = String(artifact.command_or_probe ?? '').toLowerCase();
    const target = String(artifact.artifact ?? '').toLowerCase();
    const summary = String(artifact.result_summary ?? '').toLowerCase();
    const combined = `${command} ${summary} ${target}`;
    return command.includes(requirement.commandIncludes)
      && target.includes(requirement.artifactIncludes)
      && isHTTPSNonLocalArtifact(target)
      && target.endsWith('.json')
      && !hasDisallowedStrictEvidenceMarker(combined)
      && includesAll(summary, requirement.summaryIncludes)
      && (
        !['SRC-CI-001', 'DEPLOY-TF-001', 'DEPLOY-TLS-001', 'DEPLOY-K8S-001', 'SEC-SECRETS-001', 'SEC-DBUSER-001', 'ABUSE-LIMIT-001', 'DATA-RLS-001', 'RUST-GRPC-001', 'OBS-OTEL-001', 'OBS-ALERT-001', 'CLIENT-WEB-001', 'CLIENT-MOBILE-001', 'EXT-ZOOM-001', 'EXT-AI-001', 'PERF-HTTP-001', 'PERF-WS-001', 'DATA-REDIS-001', 'DR-ROLLBACK-001', 'DR-BACKUP-001'].includes(item.id)
        || summary.includes(`release_candidate=${String(manifest.release_candidate).toLowerCase()}`)
      )
      && (item.id === 'SRC-CI-001' || summaryHasExactServiceVersion(summary, manifest.release_candidate))
      && (
        item.id !== 'SRC-CI-001'
        || (
          command.includes('-run-artifact-url')
          && command.includes('https://')
          && command.includes('ci-release-evidence')
          && !command.includes('-run-artifact-file')
          && !combined.includes('artifacts/ci-release-evidence.txt')
        )
      )
      && (!requirement.extraSummaryOrArtifactIncludes || combined.includes(requirement.extraSummaryOrArtifactIncludes));
  });
  assert.ok(
    hasRequiredProbeReport,
    `${item.id} strict release evidence must include a tools/${requirement.commandIncludes} JSON report`,
  );
  if (item.id === 'DATA-RLS-001') {
    const tenantLoadRunIDs = new Set();
    for (const [segment, markers] of tenantSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summaryHasSegmentLabel(summary, segment)
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `DATA-RLS-001 strict release evidence must include tenant markers on ${segment}`,
      );
      const loadRunID = summarySegmentCapture(findEvidenceSegment(evidence, segment), segment, /\bload_run_id=([^\s,;]+)/i);
      assert.ok(loadRunID, `DATA-RLS-001 strict release evidence must include load_run_id on ${segment}`);
      tenantLoadRunIDs.add(loadRunID);
    }
    assert.equal(tenantLoadRunIDs.size, 1, 'DATA-RLS-001 strict release evidence load_run_id values must all match');
    assertStrictTenantOrgIDBinding(evidence);
    assertStrictTenantResourceIDBinding(evidence);
  }
  if (item.id === 'DEPLOY-TLS-001') {
    const tlsLoadRunIDs = new Set();
    for (const [segment, markers] of tlsSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `DEPLOY-TLS-001 strict release evidence must include TLS/web markers on ${segment}`,
      );
      const loadRunID = summarySegmentCapture(findEvidenceSegment(evidence, segment), segment, /\bload_run_id=([^\s,;]+)/i);
      assert.ok(loadRunID, `DEPLOY-TLS-001 strict release evidence must include load_run_id on ${segment}`);
      tlsLoadRunIDs.add(loadRunID);
    }
    assert.equal(tlsLoadRunIDs.size, 1, 'DEPLOY-TLS-001 strict release evidence load_run_id values must all match');
    assertStrictTLSCertificateIdentity(evidence, 'DEPLOY-TLS-001', ['api-tls', 'web-tls']);
  }
  if (item.id === 'CLIENT-WEB-001') {
    const webLoadRunIDs = new Set();
    for (const [segment, markers] of webClientSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `CLIENT-WEB-001 strict release evidence must include web client markers on ${segment}`,
      );
      const loadRunID = summarySegmentCapture(findEvidenceSegment(evidence, segment), segment, /\bload_run_id=([^\s,;]+)/i);
      assert.ok(loadRunID, `CLIENT-WEB-001 strict release evidence must include load_run_id on ${segment}`);
      webLoadRunIDs.add(loadRunID);
    }
    assert.equal(webLoadRunIDs.size, 1, 'CLIENT-WEB-001 strict release evidence load_run_id values must all match');
    assertStrictTLSCertificateIdentity(evidence, 'CLIENT-WEB-001', ['web-tls']);
    assertStrictWebSmokeIdentityLinkage(evidence);
  }
  if (item.id === 'SEC-SECRETS-001') {
    const securityRoleARNs = new Map();
    const securityLoadRunIDs = new Set();
    for (const [segment, markers] of securitySegmentMarkerRequirements) {
      const segmentSatisfied = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summaryHasSegmentLabel(summary, segment)
          && summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        segmentSatisfied,
        true,
        `SEC-SECRETS-001 strict release evidence must include security markers on ${segment}`,
      );
      if (securityRoleARNSegments.has(segment)) {
        let roleARN = '';
        const hasConcreteRoleARN = evidence.some((artifact) => {
          const summary = String(artifact.result_summary ?? '');
          roleARN = summarySegmentCapture(summary, segment, concreteIAMRoleARNPattern);
          return roleARN !== '';
        });
        assert.equal(
          hasConcreteRoleARN,
          true,
          `SEC-SECRETS-001 strict release evidence must include concrete IAM role ARN on ${segment}`,
        );
        securityRoleARNs.set(segment, roleARN);
      }
      const loadRunID = summarySegmentCapture(findEvidenceSegment(evidence, segment), segment, /\bload_run_id=([^\s,;]+)/i);
      assert.ok(loadRunID, `SEC-SECRETS-001 strict release evidence must include load_run_id on ${segment}`);
      securityLoadRunIDs.add(loadRunID);
    }
    assertEqualStrictSecurityRoleARNs(securityRoleARNs);
    assert.equal(securityLoadRunIDs.size, 1, 'SEC-SECRETS-001 strict release evidence load_run_id values must all match');
    assertNoStrictSecretLeaks(evidence);
  }
  if (item.id === 'SEC-DBUSER-001') {
    for (const [segment, markers] of dbUserSegmentMarkerRequirements) {
      const segmentSatisfied = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summaryHasSegmentLabel(summary, segment)
          && summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        segmentSatisfied,
        true,
        `SEC-DBUSER-001 strict release evidence must include database user markers on ${segment}`,
      );
    }
    const dbUserSegment = findEvidenceSegment(evidence, 'database-scoped-user');
    assert.match(
      dbUserSegment,
      dbUserPrincipalBindingPattern,
      'SEC-DBUSER-001 database-scoped-user must bind connected user and current_user to scriptureforge_app',
    );
  }
  if (item.id === 'DR-ROLLBACK-001' || item.id === 'DR-BACKUP-001') {
    const requiredSegments = item.id === 'DR-ROLLBACK-001'
      ? ['api-ready-before-rollback', 'rollback-rollout-artifact', 'api-ready-after-rollback', 'degradation-drill-artifact']
      : ['backup-snapshot-artifact', 'restore-drill-artifact', 'restored-database-smoke'];
    for (const segment of requiredSegments) {
      const markers = resilienceSegmentMarkerRequirements.get(segment) ?? [];
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `${item.id} strict release evidence must include resilience markers on ${segment}`,
      );
    }
    if (item.id === 'DR-ROLLBACK-001') {
      assertStrictRollbackVersionLinkage(evidence);
    }
    if (item.id === 'DR-BACKUP-001') {
      assertStrictBackupRestoreSnapshotLinkage(evidence);
    }
  }
  if (item.id === 'DEPLOY-TF-001') {
    for (const [segment, markers] of terraformSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `DEPLOY-TF-001 strict release evidence must include Terraform markers on ${segment}`,
      );
    }
    const missingApplyOrApprovalMarkers = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('terraform-staging-apply-or-approval')
        && !terraformApplyOrApprovalSegmentMarkerSets.some((markers) => summarySegmentIncludesAll(summary, 'terraform-staging-apply-or-approval', markers));
    });
    assert.equal(
      missingApplyOrApprovalMarkers,
      false,
      'DEPLOY-TF-001 strict release evidence must include apply or approval markers on terraform-staging-apply-or-approval',
    );
  }
  if (item.id === 'DEPLOY-K8S-001') {
    for (const [segment, markers] of kubernetesSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `DEPLOY-K8S-001 strict release evidence must include Kubernetes markers on ${segment}`,
      );
    }
    assertStrictKubernetesImageDigests(evidence);
  }
  if (item.id === 'RUST-GRPC-001') {
    for (const [segment, markers] of rustSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `RUST-GRPC-001 strict release evidence must include Rust markers on ${segment}`,
      );
    }
    const rustMetricsSegment = findEvidenceSegment(evidence, 'rust-metrics');
    assert.match(
      rustMetricsSegment,
      rustEmbeddingRequestsPattern,
      'RUST-GRPC-001 rust-metrics must include positive embedding_requests=<count>',
    );
    assert.match(
      rustMetricsSegment,
      rustVectorSearchRequestsPattern,
      'RUST-GRPC-001 rust-metrics must include positive vector_search_requests=<count>',
    );
    const apiRustMetricsSegment = findEvidenceSegment(evidence, 'api-rust-integration-metrics');
    assert.match(
      apiRustMetricsSegment,
      apiRustVectorSearchOpsPattern,
      'RUST-GRPC-001 api-rust-integration-metrics must include positive api_rust_vector_search_ops=<count>',
    );
    assert.match(
      apiRustMetricsSegment,
      apiRustVectorSearchSecondsPattern,
      'RUST-GRPC-001 api-rust-integration-metrics must include positive api_rust_vector_search_seconds=<seconds>',
    );
    const rustLoadRunIDs = [
      'rust-grpc-health',
      'rust-metrics',
      'api-rust-integration-metrics',
    ].map((segment) => summarySegmentCapture(
      findEvidenceSegment(evidence, segment),
      segment,
      /\bload_run_id=([^\s,;]+)/i,
    ));
    assert.ok(rustLoadRunIDs.every(Boolean), 'RUST-GRPC-001 strict release evidence must include load_run_id on every Rust segment');
    assert.equal(new Set(rustLoadRunIDs).size, 1, 'RUST-GRPC-001 strict release evidence load_run_id values must all match');
  }
  if (item.id === 'CLIENT-MOBILE-001') {
    const mobileLoadRunIDs = new Set();
    const mobileBuildIDs = new Set();
    for (const [segment, markers] of mobileSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `CLIENT-MOBILE-001 strict release evidence must include mobile markers on ${segment}`,
      );
      const loadRunID = summarySegmentCapture(findEvidenceSegment(evidence, segment), segment, /\bload_run_id=([^\s,;]+)/i);
      assert.ok(loadRunID, `CLIENT-MOBILE-001 strict release evidence must include load_run_id on ${segment}`);
      mobileLoadRunIDs.add(loadRunID);
      const mobileBuildID = summarySegmentCapture(findEvidenceSegment(evidence, segment), segment, mobileBuildIDPattern);
      assert.ok(mobileBuildID, `CLIENT-MOBILE-001 strict release evidence must include mobile_build_id on ${segment}`);
      mobileBuildIDs.add(mobileBuildID);
    }
    assert.equal(mobileLoadRunIDs.size, 1, 'CLIENT-MOBILE-001 strict release evidence load_run_id values must all match');
    assert.equal(mobileBuildIDs.size, 1, 'CLIENT-MOBILE-001 strict release evidence mobile_build_id values must all match');
    const easSegment = findEvidenceSegment(evidence, 'mobile-eas-or-device-run');
    assert.match(
      easSegment,
      mobilePlatformsPattern,
      'CLIENT-MOBILE-001 mobile-eas-or-device-run must include platforms with android and ios',
    );
    assert.match(
      easSegment,
      mobileReleaseChannelPattern,
      'CLIENT-MOBILE-001 mobile-eas-or-device-run must include release_channel=staging',
    );
    assert.match(
      easSegment,
      mobileExpoProfilePattern,
      'CLIENT-MOBILE-001 mobile-eas-or-device-run must include expo_profile=staging',
    );
    const cryptoSegment = findEvidenceSegment(evidence, 'mobile-native-crypto-smoke');
    const nativeProvider = cryptoSegment.match(mobileNativeProviderPattern)?.[1] ?? '';
    const nativeRequired = cryptoSegment.match(mobileNativeRequiredPattern)?.[1] ?? '';
    assert.equal(nativeProvider, 'react-native-quick-crypto', 'CLIENT-MOBILE-001 mobile-native-crypto-smoke must bind first provider marker to react-native-quick-crypto');
    assert.equal(nativeRequired, 'true', 'CLIENT-MOBILE-001 mobile-native-crypto-smoke must bind first native_required marker to true');
    assert.match(
      cryptoSegment,
      mobileKeyDisposedPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include key_disposed=true',
    );
    assert.match(
      cryptoSegment,
      mobileDisposedHandleRejectedPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include disposed_handle_rejected=true',
    );
    assert.match(
      cryptoSegment,
      mobileRevokedKeyRejectedPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include revoked_key_rejected=true',
    );
    assert.match(
      cryptoSegment,
      mobilePassphraseZeroizedPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include passphrase_buffer_zeroized=true',
    );
    assert.match(
      cryptoSegment,
      mobileSaltZeroizedPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include salt_buffer_zeroized=true',
    );
    assert.match(
      cryptoSegment,
      mobilePlaintextZeroizedPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include plaintext_buffer_zeroized=true',
    );
    assert.match(
      cryptoSegment,
      mobileAssociatedDataSaltIDPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include concrete associated_data_salt_id',
    );
    assert.match(
      cryptoSegment,
      mobileAssociatedDataVersionPattern,
      'CLIENT-MOBILE-001 mobile-native-crypto-smoke must include positive associated_data_salt_version',
    );
    const configSegment = findEvidenceSegment(evidence, 'mobile-staging-config');
    const apiBaseURL = configSegment.match(mobileAPIBaseURLPattern)?.[1] ?? '';
    const wsBaseURL = configSegment.match(mobileWSBaseURLPattern)?.[1] ?? '';
    assert.match(
      configSegment,
      mobileAPIBaseURLPattern,
      'CLIENT-MOBILE-001 mobile-staging-config must include HTTPS EXPO_PUBLIC_API_BASE_URL=<url>',
    );
    assertNonLocalStagingEndpoint(apiBaseURL, 'CLIENT-MOBILE-001 mobile-staging-config EXPO_PUBLIC_API_BASE_URL must be a public non-placeholder staging endpoint');
    assert.match(
      configSegment,
      mobileWSBaseURLPattern,
      'CLIENT-MOBILE-001 mobile-staging-config must include WSS EXPO_PUBLIC_WS_BASE_URL=<url>',
    );
    assertNonLocalStagingEndpoint(wsBaseURL, 'CLIENT-MOBILE-001 mobile-staging-config EXPO_PUBLIC_WS_BASE_URL must be a public non-placeholder staging endpoint');
    assert.match(
      configSegment,
      mobileRequireNativeCryptoPattern,
      'CLIENT-MOBILE-001 mobile-staging-config must include EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true',
    );
    assert.match(
      configSegment,
      mobileDeploymentEnvironmentPattern,
      'CLIENT-MOBILE-001 mobile-staging-config must include EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging',
    );
  }
  if (item.id === 'PERF-HTTP-001') {
    for (const [segment, markers] of httpPerformanceSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `PERF-HTTP-001 strict release evidence must include HTTP load markers on ${segment}`,
      );
    }
    assertStrictPerformanceNumbers('PERF-HTTP-001', evidence, 'PERF-HTTP-001', {
      minRPS: 5000,
      maxP99MS: 200,
      minDurationMS: 60000,
    });
  }
  if (item.id === 'PERF-WS-001') {
    for (const [segment, markers] of websocketPerformanceSegmentMarkerRequirements) {
      assertEvidenceHasSegmentMarkers(evidence, segment, markers, `PERF-WS-001 strict release evidence must include WebSocket load markers on ${segment}`);
    }
    assertStrictWebSocketArtifactRoomBinding(evidence, 'PERF-WS-001');
    assertStrictWebSocketPrincipalBinding(evidence, 'PERF-WS-001');
    assertStrictPerformanceNumbers('PERF-WS-001', evidence, 'PERF-WS-001', {
      minRPS: 500,
      maxP99MS: 200,
      minDurationMS: 60000,
      minWSEvents: 30000,
    });
    assertStrictWebSocketSequenceNumbers(evidence, 'PERF-WS-001', 'PERF-WS-001', 30000);
  }
  if (item.id === 'DATA-REDIS-001') {
    for (const [segment, markers] of redisPerformanceSegmentMarkerRequirements) {
      assertEvidenceHasSegmentMarkers(evidence, segment, markers, `DATA-REDIS-001 strict release evidence must include Redis load markers on ${segment}`);
    }
    assertStrictWebSocketArtifactRoomBinding(evidence, 'DATA-REDIS-001');
    assertStrictWebSocketPrincipalBinding(evidence, 'DATA-REDIS-001');
    assertStrictRedisSequenceNumbers(evidence);
  }
  if (item.id === 'ABUSE-LIMIT-001') {
    const abuseLoadRunIDs = new Set();
    for (const [segment, markers] of abuseRateLimitSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `ABUSE-LIMIT-001 strict release evidence must include abuse markers on ${segment}`,
      );
      const loadRunID = summarySegmentCapture(findEvidenceSegment(evidence, segment), segment, /\bload_run_id=([^\s,;]+)/i);
      assert.ok(loadRunID, `ABUSE-LIMIT-001 strict release evidence must include load_run_id on ${segment}`);
      abuseLoadRunIDs.add(loadRunID);
    }
    assert.equal(abuseLoadRunIDs.size, 1, 'ABUSE-LIMIT-001 strict release evidence load_run_id values must all match');
    assertStrictAbuseAttempts(evidence);
    assertStrictAbuseRateLimitHeaders(evidence);
    assertStrictAbuseConfigAssignments(evidence);
  }
  if (item.id === 'DEPLOY-TF-001') {
    const approvalEvidenceWithoutTicket = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '').toLowerCase();
      return summary.includes('terraform-staging-apply-or-approval')
        && summary.includes('deployment approval')
        && summary.includes('approved')
        && summary.includes('deploy-tf-001')
        && !terraformApprovalChangeTicketPattern.test(summary);
    });
    assert.equal(
      approvalEvidenceWithoutTicket,
      false,
      'DEPLOY-TF-001 strict release approval evidence must include change_ticket=<ticket-id>',
    );
  }
  if (item.id === 'EXT-ZOOM-001') {
    const missingMeetingCreateOrFallbackProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('zoom-meeting-create-or-fallback')
        && !zoomMeetingJoinURLPattern.test(summary)
        && !zoomMeetingOfflineFallbackPattern.test(summary);
    });
    assert.equal(
      missingMeetingCreateOrFallbackProof,
      false,
      'EXT-ZOOM-001 strict release evidence must include meeting-create or offline-fallback markers on zoom-meeting-create-or-fallback',
    );
    for (const [segment, markers] of zoomSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `EXT-ZOOM-001 strict release evidence must include Zoom markers on ${segment}`,
      );
    }
    const webhookSignatureSegment = findEvidenceSegment(evidence, 'zoom-webhook-signature-delivery');
    assert.match(
      webhookSignatureSegment,
      zoomWebhookSignaturePattern,
      'EXT-ZOOM-001 zoom-webhook-signature-delivery must include concrete x-zm-signature=<v0 signature>',
    );
    assert.match(
      webhookSignatureSegment,
      zoomWebhookTimestampPattern,
      'EXT-ZOOM-001 zoom-webhook-signature-delivery must include concrete x-zm-request-timestamp=<epoch>',
    );
    assert.match(
      webhookSignatureSegment,
      zoomStaleRejectedPattern,
      'EXT-ZOOM-001 zoom-webhook-signature-delivery must include stale_rejected=true',
    );
    assert.match(
      webhookSignatureSegment,
      zoomReplayRejectedPattern,
      'EXT-ZOOM-001 zoom-webhook-signature-delivery must include replay_rejected=true',
    );
    assert.match(
      webhookSignatureSegment,
      zoomInvalidSignatureRejectedPattern,
      'EXT-ZOOM-001 zoom-webhook-signature-delivery must include invalid_signature_rejected=true',
    );
    assert.match(
      webhookSignatureSegment,
      zoomSignedDeliveryAcceptedPattern,
      'EXT-ZOOM-001 zoom-webhook-signature-delivery must include signed_delivery_accepted=true',
    );
    const timeoutCircuitSegment = findEvidenceSegment(evidence, 'zoom-timeout-circuit-fallback');
    assert.match(
      timeoutCircuitSegment,
      zoomProviderTimeoutPattern,
      'EXT-ZOOM-001 zoom-timeout-circuit-fallback must include provider_timeout=true',
    );
    assert.match(
      timeoutCircuitSegment,
      zoomCircuitOpenPattern,
      'EXT-ZOOM-001 zoom-timeout-circuit-fallback must include circuit_open=true',
    );
    assert.match(
      timeoutCircuitSegment,
      zoomOfflineFallbackPattern,
      'EXT-ZOOM-001 zoom-timeout-circuit-fallback must include offline_fallback=true',
    );
    const webhookValidationSegment = findEvidenceSegment(evidence, 'zoom-webhook-url-validation');
    assert.match(
      webhookValidationSegment,
      zoomPlainTokenPattern,
      'EXT-ZOOM-001 zoom-webhook-url-validation must include concrete plain_token=<token>',
    );
    assert.match(
      webhookValidationSegment,
      zoomEncryptedTokenPattern,
      'EXT-ZOOM-001 zoom-webhook-url-validation must include concrete encrypted_token=<token>',
    );
    assert.match(
      webhookValidationSegment,
      zoomValidationResponsePattern,
      'EXT-ZOOM-001 zoom-webhook-url-validation must include validation_response=200',
    );
    const duplicateSegment = findEvidenceSegment(evidence, 'zoom-duplicate-webhook-idempotency');
    assert.match(
      duplicateSegment,
      zoomTrackingIDPattern,
      'EXT-ZOOM-001 zoom-duplicate-webhook-idempotency must include concrete x-zm-trackingid=<id>',
    );
    assert.match(
      duplicateSegment,
      zoomDeliveryIDPattern,
      'EXT-ZOOM-001 zoom-duplicate-webhook-idempotency must include concrete delivery_id=<id>',
    );
    assert.match(
      duplicateSegment,
      zoomSingleStateMutationPattern,
      'EXT-ZOOM-001 zoom-duplicate-webhook-idempotency must include single_state_mutation=true',
    );
    assert.match(
      duplicateSegment,
      zoomNoDuplicateSideEffectsPattern,
      'EXT-ZOOM-001 zoom-duplicate-webhook-idempotency must include no_duplicate_side_effects=true',
    );
    const roomMappingSegment = findEvidenceSegment(evidence, 'zoom-meeting-room-mapping');
    assert.match(
      roomMappingSegment,
      zoomMeetingExternalIDPattern,
      'EXT-ZOOM-001 zoom-meeting-room-mapping must include concrete meeting_external_id=<id>',
    );
    assert.match(
      roomMappingSegment,
      zoomInternalRoomIDPattern,
      'EXT-ZOOM-001 zoom-meeting-room-mapping must include concrete internal_room_id=<id>',
    );
  }
  if (item.id === 'EXT-AI-001') {
    const missingCitationVerificationProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('ai-citation-verification')
        && !aiCitationVerificationPattern.test(summary);
    });
    assert.equal(
      missingCitationVerificationProof,
      false,
      'EXT-AI-001 strict release evidence must include citation rejection/acceptance markers on ai-citation-verification',
    );
    const missingAuditPersistenceProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('ai-audit-persistence')
        && !aiAuditPersistencePattern.test(summary);
    });
    assert.equal(
      missingAuditPersistenceProof,
      false,
      'EXT-AI-001 strict release evidence must include tenant-RLS audit markers on ai-audit-persistence',
    );
    const providerSegment = findEvidenceSegment(evidence, 'ai-provider-config');
    const degradationSegment = findEvidenceSegment(evidence, 'ai-timeout-degradation');
    const generationSegment = evidence
      .map((artifact) => String(artifact.result_summary ?? ''))
      .map((summary) => findEvidenceSegment([{ result_summary: summary }], 'ai-generation-route'))
      .find(Boolean);
    const citationSegment = evidence
      .map((artifact) => String(artifact.result_summary ?? ''))
      .map((summary) => findEvidenceSegment([{ result_summary: summary }], 'ai-citation-verification'))
      .find(Boolean);
    const auditSegment = evidence
      .map((artifact) => String(artifact.result_summary ?? ''))
      .map((summary) => findEvidenceSegment([{ result_summary: summary }], 'ai-audit-persistence'))
      .find(Boolean);
    assert.ok(providerSegment, 'EXT-AI-001 strict release evidence must include ai-provider-config segment');
    assert.ok(degradationSegment, 'EXT-AI-001 strict release evidence must include ai-timeout-degradation segment');
    assert.ok(generationSegment, 'EXT-AI-001 strict release evidence must include ai-generation-route segment');
    assert.ok(citationSegment, 'EXT-AI-001 strict release evidence must include ai-citation-verification segment');
    assert.ok(auditSegment, 'EXT-AI-001 strict release evidence must include ai-audit-persistence segment');
    assert.match(providerSegment, aiProviderValuePattern, 'EXT-AI-001 strict release ai-provider-config segment must include AI_PROVIDER=<provider>');
    assert.match(providerSegment, aiModelValuePattern, 'EXT-AI-001 strict release ai-provider-config segment must include AI_CHAT_MODEL=<model>');
    assert.match(providerSegment, aiEndpointValuePattern, 'EXT-AI-001 strict release ai-provider-config segment must include HTTPS AI_CHAT_ENDPOINT=<url>');
    assert.match(providerSegment, aiHTTPTimeoutMSValuePattern, 'EXT-AI-001 strict release ai-provider-config segment must include positive AI_HTTP_TIMEOUT_MS=<ms>');
    assert.match(providerSegment, aiMaxRetriesValuePattern, 'EXT-AI-001 strict release ai-provider-config segment must include AI_MAX_RETRIES=<count>');
    assert.match(degradationSegment, aiProviderTimeoutPattern, 'EXT-AI-001 strict release ai-timeout-degradation segment must include provider_timeout=true');
    assert.match(degradationSegment, aiRetryExhaustedPattern, 'EXT-AI-001 strict release ai-timeout-degradation segment must include retry_exhausted=true');
    assert.match(degradationSegment, aiFailClosedPattern, 'EXT-AI-001 strict release ai-timeout-degradation segment must include fail_closed=true');
    const generationRequestID = generationSegment.match(aiRequestIDPattern)?.[1] ?? '';
    const generationOrganizationID = generationSegment.match(aiOrganizationIDPattern)?.[1] ?? '';
    const generationUserID = generationSegment.match(aiUserIDPattern)?.[1] ?? '';
    const auditRequestID = auditSegment.match(aiRequestIDPattern)?.[1] ?? '';
    const auditOrganizationID = auditSegment.match(aiOrganizationIDPattern)?.[1] ?? '';
    const auditUserID = auditSegment.match(aiUserIDPattern)?.[1] ?? '';
    const citationID = citationSegment.match(aiCitationIDPattern)?.[1] ?? '';
    const auditCitationID = auditSegment.match(aiCitationIDPattern)?.[1] ?? '';
    assert.ok(generationRequestID, 'EXT-AI-001 strict release ai-generation-route segment must include request_id=<id>');
    assert.ok(generationOrganizationID, 'EXT-AI-001 strict release ai-generation-route segment must include organization_id=<id>');
    assert.ok(generationUserID, 'EXT-AI-001 strict release ai-generation-route segment must include user_id=<id>');
    assert.ok(auditRequestID, 'EXT-AI-001 strict release ai-audit-persistence segment must include request_id=<id>');
    assert.ok(auditOrganizationID, 'EXT-AI-001 strict release ai-audit-persistence segment must include organization_id=<id>');
    assert.ok(auditUserID, 'EXT-AI-001 strict release ai-audit-persistence segment must include user_id=<id>');
    assert.ok(citationID, 'EXT-AI-001 strict release ai-citation-verification segment must include citation_id=<id>');
    assert.ok(auditCitationID, 'EXT-AI-001 strict release ai-audit-persistence segment must include citation_id=<id>');
    assert.equal(
      auditOrganizationID,
      generationOrganizationID,
      'EXT-AI-001 strict release ai-audit-persistence organization_id must match ai-generation-route organization_id',
    );
    assert.equal(
      auditUserID,
      generationUserID,
      'EXT-AI-001 strict release ai-audit-persistence user_id must match ai-generation-route user_id',
    );
    assert.equal(
      auditRequestID,
      generationRequestID,
      'EXT-AI-001 strict release ai-audit-persistence request_id must match ai-generation-route request_id',
    );
    assert.equal(
      auditCitationID,
      citationID,
      'EXT-AI-001 strict release ai-audit-persistence citation_id must match ai-citation-verification citation_id',
    );
    for (const [segment, markers] of aiSegmentMarkerRequirements) {
      const missingSegmentMarkers = evidence.some((artifact) => {
        const summary = String(artifact.result_summary ?? '');
        return summary.toLowerCase().includes(segment.toLowerCase())
          && !summarySegmentIncludesAll(summary, segment, markers);
      });
      assert.equal(
        missingSegmentMarkers,
        false,
        `EXT-AI-001 strict release evidence must include AI markers on ${segment}`,
      );
    }
  }
  if (item.id === 'OBS-OTEL-001') {
    const missingCollectorConfigProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('collector-otlp-config')
        && !obsCollectorConfigPattern.test(summary);
    });
    assert.equal(
      missingCollectorConfigProof,
      false,
      'OBS-OTEL-001 strict release evidence must include staging OTLP markers on collector-otlp-config',
    );
    const missingAPIMetricsProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('api-prometheus-metrics')
        && !obsAPIMetricsPattern.test(summary);
    });
    assert.equal(
      missingAPIMetricsProof,
      false,
      'OBS-OTEL-001 strict release evidence must include API metric markers on api-prometheus-metrics',
    );
    const missingRustMetricsProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('rust-prometheus-metrics')
        && !obsRustMetricsPattern.test(summary);
    });
    assert.equal(
      missingRustMetricsProof,
      false,
      'OBS-OTEL-001 strict release evidence must include Rust metric markers on rust-prometheus-metrics',
    );
    const missingTraceSearchProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('trace-backend-search')
        && !obsTraceSearchPattern.test(summary);
    });
    assert.equal(
      missingTraceSearchProof,
      false,
      'OBS-OTEL-001 strict release evidence must include API/Rust trace markers on trace-backend-search',
    );
    const missingLogCorrelationProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('log-backend-trace-correlation')
        && !obsLogCorrelationPattern.test(summary);
    });
    assert.equal(
      missingLogCorrelationProof,
      false,
      'OBS-OTEL-001 strict release evidence must include tenant-aware log markers on log-backend-trace-correlation',
    );
    const traceSegment = findEvidenceSegment(evidence, 'trace-backend-search');
    const logSegment = findEvidenceSegment(evidence, 'log-backend-trace-correlation');
    const traceSegmentTraceID = extractStandaloneTraceID(traceSegment, 'trace-backend-search');
    const logSegmentTraceID = extractStandaloneTraceID(logSegment, 'log-backend-trace-correlation');
    assert.equal(
      logSegmentTraceID,
      traceSegmentTraceID,
      'OBS-OTEL-001 strict release trace/log segments must reference the same concrete trace ID',
    );
  }
  if (item.id === 'OBS-ALERT-001') {
    const missingDashboardImportProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('dashboard-import')
        && !obsDashboardImportPattern.test(summary);
    });
    assert.equal(
      missingDashboardImportProof,
      false,
      'OBS-ALERT-001 strict release evidence must include dashboard metric markers on dashboard-import',
    );
    const missingAlertRulesProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('alert-rules-loaded')
        && !obsAlertRulesPattern.test(summary);
    });
    assert.equal(
      missingAlertRulesProof,
      false,
      'OBS-ALERT-001 strict release evidence must include rule and metric markers on alert-rules-loaded',
    );
    const missingAlertDeliveryProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('alert-delivery-status')
        && !obsAlertDeliveryPattern.test(summary);
    });
    assert.equal(
      missingAlertDeliveryProof,
      false,
      'OBS-ALERT-001 strict release evidence must include delivery markers on alert-delivery-status',
    );
    const missingRetentionPolicyProof = evidence.some((artifact) => {
      const summary = String(artifact.result_summary ?? '');
      return summary.toLowerCase().includes('telemetry-retention-policy')
        && !obsRetentionPolicyPattern.test(summary);
    });
    assert.equal(
      missingRetentionPolicyProof,
      false,
      'OBS-ALERT-001 strict release evidence must include retention markers on telemetry-retention-policy',
    );
  }
}

function includesAll(text, required) {
  if (!required) {
    return true;
  }
  const markers = Array.isArray(required) ? required : [required];
  return markers.every((marker) => text.includes(String(marker).toLowerCase()));
}

function summarySegmentIncludesAll(summary, segment, markers) {
  const pattern = new RegExp(
    `${escapeRegExp(segment)}${markers.map((marker) => `(?=[^;]*${escapeRegExp(marker)})`).join('')}`,
    'i',
  );
  return pattern.test(summary);
}

function summarySegmentMatches(summary, segment, pattern) {
  return String(summary ?? '').split(';').some((candidate) => (
    summaryHasSegmentLabel(candidate, segment) && pattern.test(candidate)
  ));
}

function summarySegmentCapture(summary, segment, pattern) {
  for (const candidate of String(summary ?? '').split(';')) {
    if (!summaryHasSegmentLabel(candidate, segment)) {
      continue;
    }
    const match = candidate.match(pattern);
    if (match) {
      return match[1] ?? match[0];
    }
  }
  return '';
}

function summaryHasSegmentLabel(summary, segment) {
  const pattern = new RegExp(`(?:^|;)\\s*(?:[^;:]+:\\s*)?${escapeRegExp(segment)}(?:\\s|$|[:=])`, 'i');
  return pattern.test(summary);
}

function summaryHasExactServiceVersion(summary, releaseCandidate) {
  const release = String(releaseCandidate ?? '').trim();
  if (!release) {
    return false;
  }
  const pattern = new RegExp(`(?:^|[\\s,;])service_version=[^\\s,;]*${escapeRegExp(release)}(?:[\\s,;]|$)`, 'i');
  return pattern.test(String(summary ?? ''));
}

function assertEvidenceHasSegmentMarkers(evidence, segment, markers, message) {
  const hasSegmentWithMarkers = evidence.some((artifact) => {
    const summary = String(artifact.result_summary ?? '');
    return summarySegmentIncludesAll(summary, segment, markers);
  });
  assert.equal(hasSegmentWithMarkers, true, message);
}

function findEvidenceSegment(evidence, segment) {
  const segmentLower = String(segment).toLowerCase();
  for (const artifact of evidence) {
    const summary = String(artifact.result_summary ?? '');
    const parts = summary.split(';');
    for (const part of parts) {
      if (part.toLowerCase().includes(segmentLower)) {
        return part;
      }
    }
  }
  return '';
}

function extractNumericMarker(segmentText, marker, itemID) {
  const pattern = new RegExp(`(?:^|[\\s,])${escapeRegExp(marker)}=(-?\\d+(?:\\.\\d+)?)\\b`, 'i');
  const match = pattern.exec(segmentText);
  assert.ok(match, `${itemID} strict release evidence must include numeric ${marker}`);
  const value = Number.parseFloat(match[1]);
  assert.ok(Number.isFinite(value), `${itemID} strict release evidence ${marker} must be numeric`);
  return value;
}

function extractTextMarker(segmentText, marker, itemID) {
  const pattern = new RegExp(`(?:^|[\\s,])${escapeRegExp(marker)}=([^\\s,;]+)`, 'i');
  const match = pattern.exec(segmentText);
  assert.ok(match, `${itemID} strict release evidence must include ${marker}`);
  return String(match[1] ?? '').trim();
}

function assertStrictWebSocketArtifactRoomBinding(evidence, itemID) {
  const segmentText = findEvidenceSegment(evidence, itemID);
  assert.ok(segmentText, `${itemID} strict release evidence must include WebSocket room binding segment`);
  const wsRoomID = extractTextMarker(segmentText, 'ws_room_id', itemID);
  assert.ok(wsRoomID, `${itemID} strict release ws_room_id must not be empty`);
  for (const marker of ['ws_reconnect_room_id', 'ws_polling_room_id', 'redis_telemetry_room_id']) {
    const roomID = extractTextMarker(segmentText, marker, itemID);
    assert.equal(roomID, wsRoomID, `${itemID} strict release ${marker} must match ws_room_id`);
  }
}

function assertStrictWebSocketPrincipalBinding(evidence, itemID) {
  const segmentText = findEvidenceSegment(evidence, itemID);
  assert.ok(segmentText, `${itemID} strict release evidence must include WebSocket principal binding segment`);
  const wsUserID = extractTextMarker(segmentText, 'ws_user_id', itemID);
  const wsOrganizationID = extractTextMarker(segmentText, 'ws_organization_id', itemID);
  assert.ok(wsUserID, `${itemID} strict release ws_user_id must not be empty`);
  assert.ok(wsOrganizationID, `${itemID} strict release ws_organization_id must not be empty`);
  assert.notEqual(wsUserID, wsOrganizationID, `${itemID} strict release ws_user_id and ws_organization_id must be distinct`);
}

function extractStandaloneTraceID(segmentText, segmentName) {
  assert.ok(segmentText, `OBS-OTEL-001 strict release evidence must include ${segmentName} segment`);
  const match = /(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])/i.exec(segmentText);
  assert.ok(match, `OBS-OTEL-001 strict release ${segmentName} segment must include a concrete 32-character trace ID`);
  const traceID = match[0];
  assert.notEqual(
    traceID,
    '00000000000000000000000000000000',
    `OBS-OTEL-001 strict release ${segmentName} trace ID must not be all zeroes`,
  );
  return traceID.toLowerCase();
}

function assertStrictRollbackVersionLinkage(evidence) {
  const beforeSegment = findEvidenceSegment(evidence, 'api-ready-before-rollback');
  const afterSegment = findEvidenceSegment(evidence, 'api-ready-after-rollback');
  assert.ok(beforeSegment, 'DR-ROLLBACK-001 strict release evidence must include api-ready-before-rollback segment');
  assert.ok(afterSegment, 'DR-ROLLBACK-001 strict release evidence must include api-ready-after-rollback segment');
  const preRollbackVersion = beforeSegment.match(resiliencePreRollbackVersionPattern)?.[1] ?? '';
  const postRollbackVersion = afterSegment.match(resiliencePostRollbackVersionPattern)?.[1] ?? '';
  const rolledBackFrom = afterSegment.match(resilienceRolledBackFromPattern)?.[1] ?? '';
  const rolledBackTo = afterSegment.match(resilienceRolledBackToPattern)?.[1] ?? '';
  assert.ok(preRollbackVersion, 'DR-ROLLBACK-001 strict release api-ready-before-rollback segment must include pre_rollback_version=<version>');
  assert.ok(postRollbackVersion, 'DR-ROLLBACK-001 strict release api-ready-after-rollback segment must include post_rollback_version=<version>');
  assert.ok(rolledBackFrom, 'DR-ROLLBACK-001 strict release api-ready-after-rollback segment must include rolled_back_from=<version>');
  assert.ok(rolledBackTo, 'DR-ROLLBACK-001 strict release api-ready-after-rollback segment must include rolled_back_to=<version>');
  assert.equal(
    rolledBackFrom,
    preRollbackVersion,
    'DR-ROLLBACK-001 strict release rolled_back_from must match pre_rollback_version',
  );
  assert.equal(
    rolledBackTo,
    postRollbackVersion,
    'DR-ROLLBACK-001 strict release rolled_back_to must match post_rollback_version',
  );
  assert.notEqual(
    postRollbackVersion,
    preRollbackVersion,
    'DR-ROLLBACK-001 strict release post_rollback_version must differ from pre_rollback_version',
  );
}

function assertStrictBackupRestoreSnapshotLinkage(evidence) {
  const backupSegment = findEvidenceSegment(evidence, 'backup-snapshot-artifact');
  const restoreSegment = findEvidenceSegment(evidence, 'restore-drill-artifact');
  assert.ok(backupSegment, 'DR-BACKUP-001 strict release evidence must include backup-snapshot-artifact segment');
  assert.ok(restoreSegment, 'DR-BACKUP-001 strict release evidence must include restore-drill-artifact segment');
  const backupSnapshotID = backupSegment.match(resilienceSnapshotIDPattern)?.[1] ?? '';
  const backupKMSKeyID = backupSegment.match(resilienceKMSKeyIDPattern)?.[1] ?? '';
  const restoreSourceSnapshotID = restoreSegment.match(resilienceSourceSnapshotIDPattern)?.[1] ?? '';
  const rtoMinutes = Number.parseInt(restoreSegment.match(resilienceRTOMinutesPattern)?.[1] ?? '', 10);
  const restoreDurationMinutes = Number.parseInt(restoreSegment.match(resilienceRestoreDurationMinutesPattern)?.[1] ?? '', 10);
  assert.ok(backupSnapshotID, 'DR-BACKUP-001 strict release backup-snapshot-artifact segment must include snapshot_id=<id>');
  assert.ok(backupKMSKeyID, 'DR-BACKUP-001 strict release backup-snapshot-artifact segment must include kms_key_id=<id>');
  assert.ok(restoreSourceSnapshotID, 'DR-BACKUP-001 strict release restore-drill-artifact segment must include source snapshot_id=<id>');
  assert.equal(
    restoreSourceSnapshotID,
    backupSnapshotID,
    'DR-BACKUP-001 strict release restore source snapshot_id must match backup snapshot_id',
  );
  assert.ok(Number.isInteger(rtoMinutes) && rtoMinutes > 0, 'DR-BACKUP-001 strict release restore-drill-artifact segment must include positive rto_minutes=<minutes>');
  assert.ok(Number.isInteger(restoreDurationMinutes) && restoreDurationMinutes > 0, 'DR-BACKUP-001 strict release restore-drill-artifact segment must include positive restore_duration_minutes=<minutes>');
  assert.ok(
    restoreDurationMinutes <= rtoMinutes,
    `DR-BACKUP-001 strict release restore_duration_minutes ${restoreDurationMinutes} must be <= rto_minutes ${rtoMinutes}`,
  );
}

function assertStrictTLSCertificateIdentity(evidence, itemID, segments) {
  for (const segment of segments) {
    const segmentText = findEvidenceSegment(evidence, segment);
    assert.ok(segmentText, `${itemID} strict release evidence must include ${segment} segment`);
    assert.match(
      segmentText,
      tlsCertHostnamePattern,
      `${itemID} ${segment} must include concrete cert_hostname=<hostname>`,
    );
    assert.match(
      segmentText,
      tlsCertIssuerPattern,
      `${itemID} ${segment} must include concrete cert_issuer=<issuer>`,
    );
  }
}

function assertStrictWebSmokeIdentityLinkage(evidence) {
  const authSegment = findEvidenceSegment(evidence, 'web-auth-browser-smoke');
  const journalSegment = findEvidenceSegment(evidence, 'web-journal-browser-smoke');
  const roomSegment = findEvidenceSegment(evidence, 'web-room-browser-smoke');
  assert.ok(authSegment, 'CLIENT-WEB-001 strict release evidence must include web-auth-browser-smoke segment');
  assert.ok(journalSegment, 'CLIENT-WEB-001 strict release evidence must include web-journal-browser-smoke segment');
  assert.ok(roomSegment, 'CLIENT-WEB-001 strict release evidence must include web-room-browser-smoke segment');

  const authUserID = authSegment.match(webSmokeUserIDPattern)?.[1] ?? '';
  const authOrgID = authSegment.match(webSmokeOrganizationIDPattern)?.[1] ?? '';
  const journalUserID = journalSegment.match(webSmokeUserIDPattern)?.[1] ?? '';
  const journalOrgID = journalSegment.match(webSmokeOrganizationIDPattern)?.[1] ?? '';
  const journalID = journalSegment.match(webSmokeJournalIDPattern)?.[1] ?? '';
  const roomUserID = roomSegment.match(webSmokeUserIDPattern)?.[1] ?? '';
  const roomOrgID = roomSegment.match(webSmokeOrganizationIDPattern)?.[1] ?? '';
  const roomID = roomSegment.match(webSmokeRoomIDPattern)?.[1] ?? '';

  assert.ok(authUserID && authOrgID, 'CLIENT-WEB-001 strict release auth smoke must include concrete user_id and organization_id');
  assert.ok(journalID, 'CLIENT-WEB-001 strict release journal smoke must include concrete journal_id');
  assert.ok(roomID, 'CLIENT-WEB-001 strict release room smoke must include concrete room_id');
  assert.equal(journalUserID, authUserID, 'CLIENT-WEB-001 strict release journal smoke user_id must match auth smoke');
  assert.equal(journalOrgID, authOrgID, 'CLIENT-WEB-001 strict release journal smoke organization_id must match auth smoke');
  assert.equal(roomUserID, authUserID, 'CLIENT-WEB-001 strict release room smoke user_id must match auth smoke');
  assert.equal(roomOrgID, authOrgID, 'CLIENT-WEB-001 strict release room smoke organization_id must match auth smoke');
}

function assertStrictPerformanceNumbers(itemID, evidence, segment, { minRPS, maxP99MS, minDurationMS = 0, minWSEvents = 0 }) {
  const segmentText = findEvidenceSegment(evidence, segment);
  assert.ok(segmentText, `${itemID} strict release evidence must include a numeric load measurement segment`);
  const minObservedRPS = extractNumericMarker(segmentText, 'min_rps', itemID);
  const maxAllowedP99 = extractNumericMarker(segmentText, 'max_p99_ms', itemID);
  const productionMinDurationMS = extractNumericMarker(segmentText, 'production_min_duration_ms', itemID);
  const observedRPS = extractNumericMarker(segmentText, 'observed_rps', itemID);
  const observedP99 = extractNumericMarker(segmentText, 'observed_p99_ms', itemID);
  assert.ok(minObservedRPS >= minRPS, `${itemID} strict release min_rps ${minObservedRPS} is below required ${minRPS}`);
  assert.ok(maxAllowedP99 > 0 && maxAllowedP99 <= maxP99MS, `${itemID} strict release max_p99_ms ${maxAllowedP99} must be <= ${maxP99MS}`);
  assert.ok(productionMinDurationMS >= minDurationMS, `${itemID} strict release production_min_duration_ms ${productionMinDurationMS} is below required ${minDurationMS}`);
  if (minDurationMS > 0) {
    const observedDurationMS = extractNumericMarker(segmentText, 'duration_ms', itemID);
    assert.ok(observedDurationMS >= minDurationMS, `${itemID} strict release duration_ms ${observedDurationMS} is below required ${minDurationMS}`);
  }
  if (minWSEvents > 0) {
    const productionMinWSEvents = extractNumericMarker(segmentText, 'production_min_ws_events', itemID);
    const expectedWSEvents = extractNumericMarker(segmentText, 'ws_expected_events', itemID);
    assert.ok(productionMinWSEvents >= minWSEvents, `${itemID} strict release production_min_ws_events ${productionMinWSEvents} is below required ${minWSEvents}`);
    assert.ok(expectedWSEvents >= minWSEvents, `${itemID} strict release ws_expected_events ${expectedWSEvents} is below required ${minWSEvents}`);
  }
  if (itemID === 'PERF-HTTP-001') {
    const httpReplicaCount = extractNumericMarker(segmentText, 'http_replica_count', itemID);
    const postgresP99MS = extractNumericMarker(segmentText, 'dependency_postgres_p99_ms', itemID);
    const redisP99MS = extractNumericMarker(segmentText, 'dependency_redis_p99_ms', itemID);
    assert.ok(httpReplicaCount >= 2, `${itemID} strict release http_replica_count ${httpReplicaCount} must prove at least 2 replicas`);
    assert.ok(postgresP99MS > 0 && postgresP99MS <= maxP99MS, `${itemID} strict release dependency_postgres_p99_ms ${postgresP99MS} must be <= ${maxP99MS}`);
    assert.ok(redisP99MS > 0 && redisP99MS <= maxP99MS, `${itemID} strict release dependency_redis_p99_ms ${redisP99MS} must be <= ${maxP99MS}`);
  }
  if (itemID === 'PERF-WS-001') {
    const wsReplicaCount = extractNumericMarker(segmentText, 'ws_replica_count', itemID);
    assert.ok(wsReplicaCount >= 2, `${itemID} strict release ws_replica_count ${wsReplicaCount} must prove at least 2 replicas`);
  }
  assert.ok(observedRPS >= minRPS, `${itemID} strict release observed_rps ${observedRPS} is below required ${minRPS}`);
  assert.ok(observedP99 > 0 && observedP99 <= maxP99MS, `${itemID} strict release observed_p99_ms ${observedP99} must be <= ${maxP99MS}`);
}

function assertStrictRedisSequenceNumbers(evidence) {
  assertStrictWebSocketSequenceNumbers(evidence, 'DATA-REDIS-001', 'DATA-REDIS-001', 30000);
}

function assertStrictWebSocketSequenceNumbers(evidence, itemID, segment, minExpectedEvents) {
  const segmentText = findEvidenceSegment(evidence, segment);
  assert.ok(segmentText, `${itemID} strict release evidence must include a numeric WebSocket sequence segment`);
  const productionMinWSEvents = extractNumericMarker(segmentText, 'production_min_ws_events', itemID);
  const expectedEvents = extractNumericMarker(segmentText, 'ws_expected_events', itemID);
  const uniqueSequences = extractNumericMarker(segmentText, 'ws_unique_sequences', itemID);
  const minSequence = extractNumericMarker(segmentText, 'ws_min_sequence', itemID);
  const maxSequence = extractNumericMarker(segmentText, 'ws_max_sequence', itemID);
  const pollingLatestSequence = extractNumericMarker(segmentText, 'ws_polling_latest_sequence', itemID);
  assert.ok(productionMinWSEvents >= minExpectedEvents, `${itemID} strict release production_min_ws_events ${productionMinWSEvents} is below required ${minExpectedEvents}`);
  assert.ok(expectedEvents >= minExpectedEvents, `${itemID} strict release ws_expected_events ${expectedEvents} is below required ${minExpectedEvents}`);
  assert.equal(uniqueSequences, expectedEvents, `${itemID} strict release unique sequence count must equal expected events`);
  assert.equal(minSequence, 1, `${itemID} strict release minimum sequence must be 1`);
  assert.equal(maxSequence, expectedEvents, `${itemID} strict release maximum sequence must equal expected events`);
  assert.equal(pollingLatestSequence, maxSequence, `${itemID} strict release polling latest sequence must match maximum sequence`);
}

function assertStrictKubernetesImageDigests(evidence) {
  const segmentText = findEvidenceSegment(evidence, 'kubernetes-workload-resources');
  assert.ok(segmentText, 'DEPLOY-K8S-001 strict release evidence must include Kubernetes workload resources segment');
  const digestMatches = segmentText.match(/sha256:[0-9a-f]{64}\b/gi) ?? [];
  const uniqueDigests = new Set(digestMatches.map((digest) => digest.toLowerCase()));
  assert.ok(
    uniqueDigests.size >= 3,
    `DEPLOY-K8S-001 strict release Kubernetes workload resources must include at least 3 immutable image digests, found ${uniqueDigests.size}`,
  );
  assert.equal(
    extractNumericMarker(segmentText, 'concrete_image_digests', 'DEPLOY-K8S-001'),
    uniqueDigests.size,
    'DEPLOY-K8S-001 strict release Kubernetes workload resources concrete_image_digests must match unique image digest count',
  );
  assert.equal(
    extractNumericMarker(segmentText, 'workload_image_digests', 'DEPLOY-K8S-001'),
    kubernetesWorkloadImageDigestPatterns.size,
    'DEPLOY-K8S-001 strict release Kubernetes workload resources must include workload_image_digests=3',
  );
  for (const [workload, pattern] of kubernetesWorkloadImageDigestPatterns) {
    assert.match(
      segmentText,
      pattern,
      `DEPLOY-K8S-001 strict release Kubernetes workload resources must include immutable image digest bound to ${workload}`,
    );
  }
}

function assertStrictAbuseAttempts(evidence) {
  for (const segment of abuseRateLimitProfileSegments) {
    const segmentText = findEvidenceSegment(evidence, segment);
    assert.ok(segmentText, `ABUSE-LIMIT-001 strict release evidence must include ${segment} segment`);
    const match = /(?:after\s+(\d+)\s+attempts\b|(?:^|[\s,])attempts=(\d+)\b)/i.exec(segmentText);
    assert.ok(match, `ABUSE-LIMIT-001 strict release ${segment} segment must include a concrete attempts count`);
    const attempts = Number.parseInt(match[1] ?? match[2], 10);
    assert.ok(attempts >= 2, `ABUSE-LIMIT-001 strict release ${segment} attempts ${attempts} must be >= 2`);
  }
}

function assertStrictAbuseRateLimitHeaders(evidence) {
  for (const segment of abuseRateLimitProfileSegments) {
    const segmentText = findEvidenceSegment(evidence, segment);
    assert.ok(segmentText, `ABUSE-LIMIT-001 strict release evidence must include ${segment} segment`);
    const retryAfter = extractAbuseHeader(segmentText, 'Retry-After', segment);
    const limit = extractAbuseHeader(segmentText, 'X-RateLimit-Limit', segment);
    const remaining = extractAbuseHeader(segmentText, 'X-RateLimit-Remaining', segment);
    const reset = extractAbuseHeader(segmentText, 'X-RateLimit-Reset', segment);
    assert.ok(retryAfter > 0, `ABUSE-LIMIT-001 strict release ${segment} Retry-After must be a positive integer`);
    assert.ok(limit > 0, `ABUSE-LIMIT-001 strict release ${segment} X-RateLimit-Limit must be a positive integer`);
    assert.equal(remaining, 0, `ABUSE-LIMIT-001 strict release ${segment} X-RateLimit-Remaining must equal 0`);
    assert.ok(reset > 0, `ABUSE-LIMIT-001 strict release ${segment} X-RateLimit-Reset must be a positive integer`);
  }
}

function assertStrictAbuseConfigAssignments(evidence) {
  const segmentText = findEvidenceSegment(evidence, 'config_artifact_summary');
  assert.ok(segmentText, 'ABUSE-LIMIT-001 strict release evidence must include config_artifact_summary segment');
  for (const key of abuseConfigAssignmentKeys) {
    const pattern = new RegExp(`\\b${escapeRegExp(key)}=([0-9]+)\\b`);
    const match = pattern.exec(segmentText);
    assert.ok(match, `ABUSE-LIMIT-001 strict release config_artifact_summary must include concrete ${key}=<positive integer>`);
    const value = Number.parseInt(match[1], 10);
    assert.ok(value > 0, `ABUSE-LIMIT-001 strict release config_artifact_summary ${key} must be a positive integer`);
  }
}

function extractAbuseHeader(segmentText, headerName, segment) {
  const pattern = new RegExp(`${escapeRegExp(headerName)}="?([0-9]+)"?`, 'i');
  const match = pattern.exec(segmentText);
  assert.ok(match, `ABUSE-LIMIT-001 strict release ${segment} must include concrete ${headerName}=<integer>`);
  return Number.parseInt(match[1], 10);
}

function assertEqualStrictSecurityRoleARNs(roleARNs) {
  for (const segment of securityRoleARNSegments) {
    assert.ok(roleARNs.has(segment), `SEC-SECRETS-001 strict release evidence missing concrete IAM role ARN on ${segment}`);
  }
  assert.equal(
    new Set(roleARNs.values()).size,
    1,
    'SEC-SECRETS-001 strict release evidence role_arn values must match across IRSA, SecretProviderClass, IAM policy, and access-test segments',
  );
}

function assertStrictTenantOrgIDBinding(evidence) {
  const segment = findEvidenceSegment(evidence, 'database-rls-context-proof');
  assert.ok(segment, 'DATA-RLS-001 strict release evidence must include database-rls-context-proof segment');
  const ownerMatch = segment.match(tenantOwnerOrgIDPattern);
  const blockedMatch = segment.match(tenantBlockedOrgIDPattern);
  assert.ok(ownerMatch, 'DATA-RLS-001 database-rls-context-proof must include UUID app.current_org_id=<id>');
  assert.ok(blockedMatch, 'DATA-RLS-001 database-rls-context-proof must include UUID blocked_org_id=<id>');
  assert.notEqual(
    ownerMatch[1].toLowerCase(),
    blockedMatch[1].toLowerCase(),
    'DATA-RLS-001 database-rls-context-proof owner and blocked organization IDs must differ',
  );
}

function assertStrictTenantResourceIDBinding(evidence) {
  const journalSegments = [
    'owner-create-encrypted-journal',
    'owner-read-created-journal',
    'owner-list-contains-created-journal',
    'blocked-read-created-journal',
    'blocked-list-excludes-created-journal',
  ];
  const roomSegments = [
    'owner-create-room',
    'owner-active-rooms-contains-created-room',
    'blocked-active-rooms-excludes-created-room',
    'owner-room-state',
    'blocked-room-state-denied',
  ];
  const journalIDs = journalSegments.map((segment) => {
    const value = summarySegmentCapture(evidence.map((artifact) => String(artifact.result_summary ?? '')).join('; '), segment, tenantJournalIDPattern);
    assert.ok(value, `DATA-RLS-001 ${segment} must include concrete journal_id=<id>`);
    return value;
  });
  const roomIDs = roomSegments.map((segment) => {
    const value = summarySegmentCapture(evidence.map((artifact) => String(artifact.result_summary ?? '')).join('; '), segment, tenantRoomIDPattern);
    assert.ok(value, `DATA-RLS-001 ${segment} must include concrete room_id=<id>`);
    return value;
  });
  assert.equal(
    new Set(journalIDs).size,
    1,
    'DATA-RLS-001 strict release journal_id values must match across created journal read/list/blocked segments',
  );
  assert.equal(
    new Set(roomIDs).size,
    1,
    'DATA-RLS-001 strict release room_id values must match across created room list/state/blocked segments',
  );
}

function assertNoStrictSecretLeaks(evidence) {
  for (const artifact of evidence) {
    const summary = String(artifact.result_summary ?? '').toLowerCase();
    for (const marker of strictSecretLeakMarkers) {
      assert.equal(
        summary.includes(marker),
        false,
        `SEC-SECRETS-001 strict release evidence must not include secret value marker ${marker}`,
      );
    }
  }
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function validateStrictSignoffEvidence(item, manifest) {
  const releaseMarker = `release_candidate=${String(manifest.release_candidate).toLowerCase()}`;
  const evidence = Array.isArray(item.evidence) ? item.evidence : [];
  const hasSignoffEvidence = evidence.some((artifact) => {
    const summary = String(artifact.result_summary ?? '').toLowerCase();
    const artifactText = String(artifact.artifact ?? '').toLowerCase();
    const command = String(artifact.command_or_probe ?? '').toLowerCase();
    return !hasDisallowedStrictEvidenceMarker(`${command} ${artifactText} ${summary}`)
      && isDurableSignoffArtifact(artifact.artifact)
      && requiredSignoffSummaryMarkers.every((marker) => summary.includes(marker.toLowerCase()))
      && summary.includes(releaseMarker);
  });
  assert.ok(
    hasSignoffEvidence,
    `${item.id} strict release evidence must include durable security signoff artifact, threat-model, dependency-risk, residual-risk, owner/security approval, release signoff, and exact release_candidate markers`,
  );
}

function isDurableSignoffArtifact(artifact) {
  const value = String(artifact ?? '').trim();
  if (/^https:\/\//i.test(value)) {
    return isHTTPSNonLocalArtifact(value);
  }
  const normalized = value.replaceAll('\\', '/').toLowerCase();
  return normalized.startsWith('security/')
    && normalized.endsWith('.md')
    && /signoff|approval|release-risk|risk-signoff/.test(normalized);
}

function isHTTPSNonLocalArtifact(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return url.protocol === 'https:'
    && !isLocalOrPrivateHost(hostname);
}

function assertNonLocalStagingEndpoint(value, message) {
  let url;
  try {
    url = new URL(String(value ?? '').trim());
  } catch {
    assert.fail(message);
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  assert.ok(!isLocalOrPrivateHost(hostname), message);
}

function isLocalOrPrivateHost(hostname) {
  if (isReservedPlaceholderHost(hostname)) {
    return true;
  }
  if (
    hostname === 'localhost'
    || hostname === '::'
    || hostname === '::1'
    || hostname.endsWith('.local')
    || hostname === '0.0.0.0'
    || hostname.startsWith('0.')
    || hostname.startsWith('127.')
    || hostname.startsWith('10.')
    || hostname.startsWith('192.168.')
    || /^169\.254\./.test(hostname)
  ) {
    return true;
  }
  const mappedIPv4 = ipv4MappedHost(hostname);
  if (mappedIPv4) {
    return isLocalOrPrivateHost(mappedIPv4);
  }
  if (/^f[cd][0-9a-f]*:/i.test(hostname) || /^fe[89ab][0-9a-f]*:/i.test(hostname)) {
    return true;
  }
  const private172 = hostname.match(/^172\.(\d+)\./);
  return Boolean(private172 && Number(private172[1]) >= 16 && Number(private172[1]) <= 31);
}

function isReservedPlaceholderHost(hostname) {
  const normalized = String(hostname ?? '').replace(/\.$/, '').toLowerCase();
  return normalized === 'example'
    || normalized.endsWith('.example')
    || normalized === 'example.com'
    || normalized.endsWith('.example.com')
    || normalized === 'example.org'
    || normalized.endsWith('.example.org')
    || normalized === 'example.net'
    || normalized.endsWith('.example.net')
    || normalized === 'invalid'
    || normalized.endsWith('.invalid')
    || normalized === 'test'
    || normalized.endsWith('.test');
}

function ipv4MappedHost(hostname) {
  if (!hostname.startsWith('::ffff:')) {
    return null;
  }
  const mapped = hostname.slice('::ffff:'.length);
  if (mapped.includes('.')) {
    return mapped;
  }
  const hextets = mapped.split(':').filter(Boolean).map((part) => Number.parseInt(part, 16));
  if (hextets.length === 0 || hextets.length > 2 || hextets.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) {
    return null;
  }
  const value = hextets.length === 1 ? hextets[0] : (hextets[0] << 16) + hextets[1];
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join('.');
}

function hasDisallowedStrictEvidenceMarker(value) {
  return disallowedStrictEvidenceMarkers.some((marker) => value.includes(marker));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = JSON.parse(await readFile(args.evidenceFile, 'utf8'));
  const result = validateManifest(manifest, { strictRelease: args.strictRelease });
  const strictSuffix = args.strictRelease ? ' in strict release mode' : '';
  console.log(`staging evidence manifest validated${strictSuffix}: ${args.evidenceFile} (${result.items} items): ${stagingEvidenceProofMarkers.join(', ')}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-staging-evidence.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
