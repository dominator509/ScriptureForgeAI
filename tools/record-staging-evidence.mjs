import assert from 'node:assert/strict';
import net from 'node:net';
import { readFile, writeFile } from 'node:fs/promises';
import { ciReleaseEvidenceProofMarkers } from './write-ci-release-evidence.mjs';

function usage() {
  return [
    'Usage:',
    '  node tools/record-staging-evidence.mjs --manifest <path> --probe-report <path> --artifact <path-or-url> --command <command>',
    '  node tools/record-staging-evidence.mjs --manifest <path> --item-id <ID> --artifact <path-or-url> --command <command> --summary <summary> [--observed-at <ISO-UTC>]',
    '  node tools/record-staging-evidence.mjs --manifest <path> --item-id <ID> --status blocked|failed --owner <owner> --blocker <reason>',
    '  node tools/record-staging-evidence.mjs --manifest <path> --item-id <ID> --status accepted_risk --decision-ref <record> --owner <owner> --accepted-by <name> --review-due-at <YYYY-MM-DD> --expires-at <YYYY-MM-DD>',
    '',
    'The probe report must include threshold_pass=true and evidence_items[].',
  ].join('\n');
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key?.startsWith('--') || value == null) {
      throw new Error(usage());
    }
    args[key.slice(2)] = value;
  }
  if (!args.manifest) {
    throw new Error(`missing --manifest\n${usage()}`);
  }
  if (!args['probe-report'] && !args['item-id']) {
    throw new Error(`missing --probe-report or --item-id\n${usage()}`);
  }
  if (args['probe-report'] && args['item-id']) {
    throw new Error(`choose only one of --probe-report or --item-id\n${usage()}`);
  }
  if (args['probe-report']) {
    for (const required of ['artifact', 'command']) {
      if (!args[required]) {
        throw new Error(`missing --${required}\n${usage()}`);
      }
    }
  }
  if (args['item-id'] && !args.status) {
    for (const required of ['artifact', 'command', 'summary']) {
      if (!args[required]) {
        throw new Error(`missing --${required} for --item-id evidence mode\n${usage()}`);
      }
    }
  }
  if (args.status && !['blocked', 'failed', 'accepted_risk'].includes(args.status)) {
    throw new Error(`invalid --status ${args.status}\n${usage()}`);
  }
  if ((args.status === 'blocked' || args.status === 'failed') && (!args.owner || !args.blocker)) {
    throw new Error(`--status ${args.status} requires --owner and --blocker\n${usage()}`);
  }
  if (args.status === 'accepted_risk') {
    for (const required of ['decision-ref', 'owner', 'accepted-by', 'review-due-at', 'expires-at']) {
      if (!args[required]) {
        throw new Error(`--status accepted_risk requires --${required}\n${usage()}`);
      }
    }
  }
  return args;
}

function summarizeProbeReport(report) {
  const passed = report.probes?.filter((probe) => probe.passed).length ?? 0;
  const failed = report.probes?.filter((probe) => !probe.passed).length ?? 0;
  const names = report.probes?.map((probe) => `${probe.name}:${probe.passed ? 'pass' : 'fail'}`).join(', ') ?? 'no probes';
  const releaseCandidate = String(report.commit_sha ?? '').trim();
  const releaseMarker = releaseCandidate ? ` release_candidate=${releaseCandidate}` : '';
  const probeSummaries = report.probes
    ?.map((probe) => String(probe.result_summary ?? '').trim())
    .filter(Boolean)
    .join('; ');
  const summaryMarker = probeSummaries ? `; probe summaries: ${probeSummaries}` : '';
  const abuseConfigSummary = report.evidence_items?.includes('ABUSE-LIMIT-001')
    ? String(report.config_artifact_summary ?? '').trim()
    : '';
  const abuseConfigMarker = abuseConfigSummary
    ? `; config_artifact_verified=${report.config_artifact_verified === true}; config_artifact_summary ${abuseConfigSummary}`
    : '';
  return `${passed} probes passed, ${failed} probes failed (${names})${releaseMarker}${summaryMarker}${abuseConfigMarker}`;
}

const productionPerformanceTargets = {
  'PERF-HTTP-001': {
    minRPS: 5000,
    maxP99MS: 200,
    minDurationMS: 60000,
    targetPattern: /^https:\/\//,
    targetDescription: 'HTTPS staging target',
  },
  'PERF-WS-001': {
    minRPS: 500,
    maxP99MS: 200,
    minDurationMS: 60000,
    minExpectedEvents: 30000,
    targetPattern: /^wss:\/\//,
    targetDescription: 'WSS staging target',
  },
};

const requiredPerformanceSummaryMarkers = {
  'PERF-HTTP-001': ['staging_http', 'https://', 'min_rps', '5000', 'max_p99_ms', '200', 'production_target_rps=5000', 'production_target_p99_ms=200', 'production_min_duration_ms=60000', 'duration_ms>=60000', 'observed_rps', 'observed_p99_ms', 'threshold_pass=true', 'release_candidate', 'service_version', 'load_run_id=', 'http_replica_artifact_url', 'http_replica_artifact_verified', 'http_replica_count=', 'dependency_telemetry_artifact_url', 'dependency_telemetry_artifact_verified', 'dependency_latency_artifact_verified=true', 'dependency_postgres_p99_ms=', 'dependency_redis_p99_ms='],
  'PERF-WS-001': ['staging artifact', 'staging_websocket', 'wss://', 'min_rps', '500', 'max_p99_ms', '200', 'production_target_rps=500', 'production_target_p99_ms=200', 'production_min_duration_ms=60000', 'duration_ms>=60000', 'production_min_ws_events=30000', 'observed_rps', 'observed_p99_ms', 'threshold_pass=true', 'release_candidate', 'service_version', 'load_run_id=', 'ws_sequence_contiguous=true', 'ws_origin=https://', 'ws_room_id=', 'ws_user_id=', 'ws_organization_id=', 'ws_reconnect_room_id=', 'ws_polling_room_id=', 'redis_telemetry_room_id=', 'ws_authenticated=true', 'ws_expected_events', 'ws_unique_sequences', 'ws_min_sequence', 'ws_max_sequence', 'ws_polling_latest_sequence', 'ws_replica_artifact_url=https://', 'ws_replica_artifact_verified', 'ws_replica_count=', 'ws_reconnect_artifact_url=https://', 'ws_reconnect_artifact_verified', 'ws_reconnect_sequence_continues=true', 'ws_polling_artifact_url=https://', 'ws_polling_artifact_verified', 'ws_polling_artifact_latest_sequence_validated=true', 'ws_polling_artifact_latest_sequence_matches_run=true', 'redis_telemetry_artifact_url=https://', 'redis_telemetry_artifact_verified', 'ws_distinct_artifacts=true', 'room_broadcast_drops=0'],
  'DATA-REDIS-001': ['staging artifact', 'staging_websocket', 'release_candidate', 'service_version', 'load_run_id=', 'ws_room_id=', 'ws_user_id=', 'ws_organization_id=', 'ws_reconnect_room_id=', 'ws_polling_room_id=', 'redis_telemetry_room_id=', 'ws_sequence_contiguous=true', 'production_min_ws_events=30000', 'ws_expected_events', 'ws_unique_sequences', 'ws_min_sequence', 'ws_max_sequence', 'ws_polling_latest_sequence', 'ws_polling_artifact_url=https://', 'ws_polling_artifact_latest_sequence_validated=true', 'ws_polling_artifact_latest_sequence_matches_run=true', 'redis_telemetry_artifact_url=https://', 'redis_telemetry_artifact_verified', 'ws_distinct_artifacts=true', 'room_broadcast_drops=0'],
};

const forbiddenPerformanceSummaryMarkers = [
  'threshold failed',
  'threshold failure',
  'threshold_failures',
  'rps below threshold',
  'p99 above threshold',
];

const performanceEvidenceItemIDs = ['PERF-HTTP-001', 'PERF-WS-001', 'DATA-REDIS-001'];

const requiredTenantRLSContextMarkers = [
  'staging artifact',
  'current_user=scriptureforge_app',
  'non-superuser',
  'superuser=false',
  'bypassrls=false',
  'app.current_org_id',
  "current_setting('app.current_org_id')",
  'row_security=on',
  'FORCE ROW LEVEL SECURITY',
  'rls_tables_verified=9',
  'rls_forced_tables=9',
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
  'same-tenant read visible',
  'cross-tenant read hidden',
  'cross-tenant write denied',
  'auth_refresh_session_rls=true',
  'auth_mfa_rls=true',
  'workspace_switch_tenant_match=true',
  'privileged_mfa_enrollment_rls=true',
  'ai_audit_rls=true',
  'generated_curriculum_audit_rls=true',
  'distinct_db_rls_artifact=true',
];

const requiredTenantAPIProbeSummaryMarkers = new Map([
  ['owner-create-encrypted-journal', ['same-tenant journal write accepted', 'encrypted journal created', 'plaintext not returned', 'plaintext-shaped journal payload denied', 'malformed encrypted envelope rejected']],
  ['blocked-journal-tenant-override-write-denied', ['cross-tenant journal write denied', 'tenant override rejected']],
  ['owner-read-created-journal', ['same-tenant journal read visible', 'created journal returned']],
  ['owner-list-contains-created-journal', ['same-tenant journal list visible', 'created journal present']],
  ['blocked-read-created-journal', ['cross-tenant journal read denied', 'created journal hidden']],
  ['blocked-list-excludes-created-journal', ['cross-tenant journal list hidden', 'created journal absent']],
  ['owner-create-room', ['same-tenant room write accepted', 'room created']],
  ['blocked-room-tenant-override-write-denied', ['cross-tenant room write denied', 'tenant override rejected']],
  ['owner-active-rooms-contains-created-room', ['same-tenant room list visible', 'created room present']],
  ['blocked-active-rooms-excludes-created-room', ['cross-tenant room list hidden', 'created room absent']],
  ['owner-room-state', ['same-tenant room state visible', 'created room state returned']],
  ['blocked-room-state-denied', ['cross-tenant room state denied', 'created room state hidden']],
]);

const concreteIAMRoleARNPattern = /\brole_arn=arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]+\b/i;
const requiredAppGrantTableNames = [
  'organizations',
  'users',
  'scripture_texts',
  'refresh_tokens',
  'journal_entries',
  'live_rooms',
  'room_participants',
  'ai_request_logs',
  'citation_trails',
];

const requiredSecurityProbeSummaryMarkers = new Map([
  ['irsa-service-account', ['staging artifact', 'namespace=staging', 'service_account=scriptureforge-api', 'role_arn=arn:aws:iam::', 'eks.amazonaws.com/role-arn', 'scriptureforge', 'trust policy', 'sts:AssumeRoleWithWebIdentity']],
  ['secret-provider-class', ['staging artifact', 'namespace=staging', 'service_account=scriptureforge-api', 'role_arn=arn:aws:iam::', 'SecretProviderClass', 'secrets-store.csi.k8s.io', 'provider', 'aws', 'objects', 'objectName', 'objectType', 'secretsmanager', 'objectAlias', 'jmesPath', 'secretObjects', 'type', 'Opaque', 'DATABASE_URL', 'JWT_SECRET_KEY', 'OPENAI_API_KEY', 'ZOOM_WEBHOOK_SECRET_TOKEN']],
  ['synced-secret-metadata-redacted', ['staging artifact', 'namespace=staging', 'scriptureforge-runtime-secrets', 'type', 'Opaque', 'DATABASE_URL', 'JWT_SECRET_KEY', 'OPENAI_API_KEY', 'ZOOM_WEBHOOK_SECRET_TOKEN', 'redacted', 'stringData absent', 'managed by secrets-store.csi.k8s.io', 'ownerReferences', 'secrets-store.csi.k8s.io/managed=true']],
  ['iam-secrets-policy', ['staging artifact', 'role_arn=arn:aws:iam::', 'secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret', 'arn:aws:secretsmanager:', 'scoped resource', 'no wildcard resources']],
  ['scoped-secrets-access-test', ['staging artifact', 'namespace=staging', 'service_account=scriptureforge-api', 'role_arn=arn:aws:iam::', 'allowed', 'configured secret', 'denied', 'unscoped secret', 'AccessDenied', 'distinct_secret_artifacts=true']],
]);

const securityRoleARNProbeNames = new Set([
  'irsa-service-account',
  'secret-provider-class',
  'iam-secrets-policy',
  'scoped-secrets-access-test',
]);

const requiredSecuritySignoffSummaryMarkers = [
  'threat model approval',
  'security/dependency_risk_register.md#DRR-001',
  'dependency risk decision',
  'residual risk review',
  'owner/security approval',
  'release risk signoff',
  'signoff_artifact_verified=true',
  'release_candidate=',
];

const requiredTerraformProbeSummaryMarkers = new Map([
  ['terraform-remote-backend-init', ['staging artifact', 'terraform', 's3', 'backend', 'bucket', 'key', 'encrypt=true', 'kms_key_id=', 'versioning=enabled', 'dynamodb_table', 'successfully initialized', 'release_candidate=', 'service_version=']],
  ['terraform-staging-plan', ['staging artifact', 'Terraform', 'Plan:', 'aws_eks_cluster', 'aws_eks_node_group', 'aws_rds_cluster', 'aws_elasticache_replication_group', 'aws_ecr_repository', 'kubernetes_deployment', 'kubernetes_ingress_v1', 'kubernetes_horizontal_pod_autoscaler_v2', 'kubernetes_pod_disruption_budget_v1', 'kubernetes_manifest', 'aws_iam_role', 'kms_key_id', 'database_kms_key_arn', 'redis_kms_key_arn', 'release_candidate=', 'service_version=']],
]);

const terraformApplyOrApprovalSummaryMarkerSets = [
  ['staging artifact', 'Apply complete', 'Resources:', '0 destroyed', 'release_candidate', 'service_version', 'distinct_terraform_artifacts=true'],
  ['staging artifact', 'deployment approval', 'approved', 'DEPLOY-TF-001', 'change_ticket=', 'release_candidate', 'service_version', 'distinct_terraform_artifacts=true'],
];
const terraformApprovalChangeTicketPattern = /\bchange_ticket=[A-Z][A-Z0-9]+-\d+\b/;
const immutableImageDigestPattern = /sha256:[a-fA-F0-9]{64}/g;
const kubernetesWorkloadImageDigestPatterns = new Map([
  ['scriptureforge-api', /(?:scriptureforge-api|scriptureforge\/api)[^\s,;]*@sha256:[a-fA-F0-9]{64}\b/],
  ['scriptureforge-web', /(?:scriptureforge-web|scriptureforge\/web)[^\s,;]*@sha256:[a-fA-F0-9]{64}\b/],
  ['scriptureforge-rust-engine', /(?:scriptureforge-rust-engine|scriptureforge\/rust-engine)[^\s,;]*@sha256:[a-fA-F0-9]{64}\b/],
]);
const zoomDeliveryIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const zoomTrackingIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const zoomMappingIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const zoomWebhookSignaturePattern = /^v0[:=][0-9a-f]{64}$/i;
const zoomWebhookTimestampPattern = /^[0-9]{10,}$/;
const zoomValidationTokenPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const zoomValidationResponsePattern = /^200$/;
const resilienceIdentifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const resilienceKMSKeyIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:/=-]*$/;
const aiRequestIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const aiCitationIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const aiPrincipalIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const aiProviderPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const aiModelPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const aiEndpointPattern = /^https:\/\/\S+$/;
const aiPositiveIntegerPattern = /^[1-9][0-9]*$/;
const aiNonNegativeIntegerPattern = /^[0-9]+$/;
const observabilityMethodPattern = /^[A-Z]+$/;
const observabilityPrincipalPattern = /^\S+$/;
const observabilityDeliveryIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const mobilePlatformsPattern = /^(?=.*\bandroid\b)(?=.*\bios\b)[A-Za-z0-9_,.-]+$/i;
const mobileReleaseChannelPattern = /^staging$/i;
const mobileExpoProfilePattern = /^staging$/i;
const mobileAPIBaseURLPattern = /^https:\/\/\S+$/;
const mobileWSBaseURLPattern = /^wss:\/\/\S+$/;
const mobileRequireNativeCryptoPattern = /^true$/i;
const mobileDeploymentEnvironmentPattern = /^staging$/i;
const mobileNativeProviderPattern = /^react-native-quick-crypto$/;
const mobileNativeRequiredPattern = /^true$/i;
const mobileUniqueIVPattern = /^true$/i;
const mobileBuildIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const mobileBuildIDSummaryPattern = /\bmobile_build_id=([A-Za-z0-9][A-Za-z0-9._:-]*)\b/i;
const mobileNativeProviderSummaryPattern = /\bprovider=([A-Za-z0-9_.:-]+)\b/i;
const mobileNativeRequiredSummaryPattern = /\bnative_required=(true|false)\b/i;
const mobileAssociatedDataSaltIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const mobileAssociatedDataVersionPattern = /^[1-9][0-9]*$/;
const mobileAssociatedDataSaltIDSummaryPattern = /\bassociated_data_salt_id=([A-Za-z0-9][A-Za-z0-9._:/-]*)\b/i;
const mobileAssociatedDataVersionSummaryPattern = /\bassociated_data_salt_version=([1-9][0-9]*)\b/i;
const tenantResourceIDPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const tenantOrgIDPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const requiredKubernetesProbeSummaryMarkers = new Map([
  ['kubernetes-rollout-status', ['staging artifact', 'namespace', 'staging', 'deployment', 'scriptureforge-api', 'scriptureforge-web', 'scriptureforge-rust-engine', 'successfully rolled out', 'ready', 'available', 'release_candidate', 'service_version']],
  ['kubernetes-workload-resources', ['staging artifact', 'namespace', 'staging', 'deployment', 'service', 'ingress', 'hpa', 'pdb', 'ready', 'available', 'targets', 'minavailable', 'readinessProbe', 'livenessProbe', 'rollingUpdate', 'maxUnavailable=0', 'minReplicas', 'maxReplicas', 'tls', 'SecretProviderClass', 'image', 'sha256:', 'release_candidate', 'service_version', 'scriptureforge-api', 'scriptureforge-web', 'scriptureforge-rust-engine', 'concrete_image_digests=3', 'workload_image_digests=3', 'distinct_kubernetes_artifacts=true']],
]);

const forbiddenDeploymentSummaryMarkers = [
  'terraform init failed',
  'terraform plan failed',
  'terraform apply failed',
  'apply failed',
  'plan failed',
  'rollout failed',
  'rollout status failed',
  'not rolled out',
  'availableReplicas: 0',
  'available replicas: 0',
  'readyReplicas: 0',
  'ready replicas: 0',
  'CrashLoopBackOff',
  'ImagePullBackOff',
];

const requiredStagingProbeSummaryMarkers = new Map([
  ['api-live', ['api-live', '/live', 'HTTP 200']],
  ['api-ready', ['api-ready', '/ready', 'HTTP 200']],
  ['api-tls', ['api-tls', 'TLS', 'certificate', 'cert_not_after', 'cert_hostname=', 'cert_issuer=']],
  ['api-http-redirect', ['api-http-redirect', 'HTTP', 'HTTPS', 'redirect']],
  ['web-root', ['web-root', 'web root', 'HTTP 200']],
  ['web-tls', ['web-tls', 'TLS', 'certificate', 'cert_not_after', 'cert_hostname=', 'cert_issuer=']],
  ['web-http-redirect', ['web-http-redirect', 'HTTP', 'HTTPS', 'redirect']],
]);

const requiredResilienceProbeSummaryMarkers = new Map([
  ['api-ready-before-rollback', ['staging artifact', 'ready', 'service_version', 'deployment_environment', 'pre_rollback_version', 'release_candidate']],
  ['rollback-rollout-artifact', ['staging artifact', 'rollout', 'undo', 'revision', 'previous_revision', 'target_revision', 'scriptureforge-api', 'successfully rolled out']],
  ['api-ready-after-rollback', ['staging artifact', 'ready', 'service_version', 'deployment_environment', 'post_rollback_version', 'rolled_back_from', 'rolled_back_to']],
  ['degradation-drill-artifact', ['staging artifact', 'AI', 'Zoom', 'degradation', 'fallback', 'AI_ORCHESTRATION_ENGINE_FAULT', 'offline://in-person', 'non-AI routes healthy', 'zoom circuit open', 'ai_fault=true', 'zoom_offline_fallback=true', 'non_ai_routes_healthy=true', 'zoom_circuit_open=true', 'distinct_rollback_artifacts=true']],
  ['backup-snapshot-artifact', ['staging artifact', 'snapshot', 'snapshot_id', 'available', 'encrypted', 'kms_key_id=', 'retention', 'automated backup', 'source cluster', 'rpo_minutes']],
  ['restore-drill-artifact', ['staging artifact', 'restore', 'restore_job_id', 'available', 'staging', 'restored endpoint', 'source snapshot_id', 'checksum', 'isolated restore', 'rto_minutes', 'restore_duration_minutes']],
  ['restored-database-smoke', ['staging artifact', 'smoke passed', 'restored database', 'tenant', 'journal', 'auth', 'RLS', 'migration version', 'no plaintext journal', 'distinct_backup_artifacts=true']],
]);

const forbiddenResilienceSummaryMarkers = [
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

const requiredZoomProbeSummaryMarkers = new Map([
  ['zoom-oauth-readiness', ['staging artifact', 'oauth', 'account_credentials', 'status', 'ok']],
  ['zoom-timeout-circuit-fallback', ['staging artifact', 'timeout', 'provider timeout', 'circuit', 'open', 'circuit_open_fallback', 'fallback', 'offline://in-person']],
  ['zoom-webhook-signature-delivery', ['staging artifact', 'webhook', 'signature', 'x-zm-signature=', 'x-zm-request-timestamp=', 'stale', 'replay', '401', 'invalid', 'signed', '200']],
  ['zoom-webhook-url-validation', ['staging artifact', 'endpoint.url_validation', 'plain_token=', 'encrypted_token=', 'validation_response=200']],
  ['zoom-duplicate-webhook-idempotency', ['staging artifact', 'duplicate', 'x-zm-trackingid=', 'delivery_id=', 'delivery id', 'same Zoom event', 'idempotent', '200', 'single state mutation', 'no duplicate side effects', 'single_state_mutation=true', 'no_duplicate_side_effects=true']],
  ['zoom-meeting-room-mapping', ['staging artifact', 'meeting_external_id=', 'live_rooms', 'internal_room_id=', 'redis room state', 'mapped', 'unknown meeting ignored', 'no external meeting id fallback', 'distinct_zoom_artifacts=true']],
]);

const zoomMeetingCreateOrFallbackSummaryMarkerSets = [
  ['staging artifact', 'meeting', 'join_url', 'zoom.us'],
  ['staging artifact', 'offline://in-person', 'fallback', 'Zoom'],
];

const forbiddenZoomProbeSummaryMarkers = [
  'signature verification disabled',
  'webhook signature disabled',
  'signature verification bypassed',
  'skip signature verification',
];

const requiredAIProbeSummaryMarkers = new Map([
  ['ai-provider-config', ['staging artifact', 'AI_PROVIDER', 'AI_CHAT_MODEL', 'AI_CHAT_ENDPOINT', 'AI_HTTP_TIMEOUT_MS', 'AI_MAX_RETRIES', 'OPENAI_API_KEY redacted', 'configured']],
  ['ai-generation-route', ['staging artifact', '/api/v1/ai/generate/study', 'authenticated', 'JWT claims', 'organization_id=', 'user_id=', 'request_id=', '200', 'generated_curriculum', '[Genesis 1:1]']],
  ['ai-timeout-degradation', ['staging artifact', 'provider timeout', 'degradation', 'retry exhausted', '503', 'fail closed', 'AI_ORCHESTRATION_ENGINE_FAULT']],
  ['ai-citation-verification', ['staging artifact', 'no-citation rejected', 'hallucinated citation rejected', 'verified citation accepted', 'citation_trails', 'citation_id=']],
  ['ai-audit-persistence', ['staging artifact', 'ai_request_logs', 'citation_trails', 'organization_id=', 'user_id=', 'request_id=', 'citation_id=', 'succeeded', 'failed', 'verified', 'tenant rls', 'cross-tenant hidden', 'distinct_ai_artifacts=true']],
]);

const forbiddenAIProbeSummaryMarkers = [
  'citation verification disabled',
  'citations disabled',
  'skip citation verification',
  'audit logging disabled',
  'audit persistence disabled',
  'ai_request_logs disabled',
  'citation_trails disabled',
];

const requiredAbuseProbeSummaryMarkers = new Map([
  ['auth-rate-limit', ['staging artifact', 'auth-rate-limit', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']],
  ['auth-account-rate-limit', ['staging artifact', 'auth-account-rate-limit', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'account-scoped login', 'account_scoped=true', 'rotating forwarded client IP', 'forwarded_client_ip_rotated=true']],
  ['auth-refresh-rate-limit', ['staging artifact', 'auth-refresh-rate-limit', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'refresh token', 'refresh_token_scoped=true']],
  ['ai-rate-limit', ['staging artifact', 'ai-rate-limit', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']],
  ['journal-rate-limit', ['staging artifact', 'journal-rate-limit', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']],
  ['rooms-rate-limit', ['staging artifact', 'rooms-rate-limit', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']],
  ['websocket-rate-limit', ['staging artifact', 'websocket-rate-limit', '429', 'after', 'attempts', 'repeated_attempts_verified=true', 'Retry-After', 'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'websocket upgrade', 'websocket_upgrade=true']],
]);

const requiredAbuseConfigSummaryMarkers = [
  'staging artifact',
  'ABUSE_LIMIT_AUTH_REQUESTS=',
  'ABUSE_LIMIT_AUTH_WINDOW_SECONDS=',
  'ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=',
  'ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=',
  'ABUSE_LIMIT_AI_REQUESTS=',
  'ABUSE_LIMIT_JOURNAL_REQUESTS=',
  'ABUSE_LIMIT_ROOMS_REQUESTS=',
  'ABUSE_LIMIT_WEBSOCKET_REQUESTS=',
  'ABUSE_LIMIT_MAX_BUCKETS=',
  'TRUST_PROXY_HEADERS=true',
  'X-Forwarded-For',
  'X-Real-IP',
  'redacted',
  'distinct_abuse_artifacts=true',
];

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

const requiredMobileProbeSummaryMarkers = new Map([
  ['mobile-eas-or-device-run', ['staging artifact', 'eas', 'build', 'finished', 'android', 'ios', 'native device', 'installed app', 'release channel staging', 'expo profile staging', 'distinct_mobile_artifacts=true']],
  ['mobile-native-crypto-smoke', ['staging artifact', 'runJournalCryptoSelfTest', 'react-native-quick-crypto', 'native provider', 'native module loaded', 'provider status react-native-quick-crypto', 'provider=react-native-quick-crypto', 'native-required true', 'native_required=true', 'AES-GCM', 'round-trip', 'unique_iv=true', 'unique IV', 'tamper rejected', 'associated data', 'wrong associated data rejected', 'associated_data_salt_id=', 'associated_data_salt_version=', 'non-extractable', 'provider-bound key', 'fallback-derived key rejected', 'key disposed', 'disposed handle rejected', 'revoked_key_rejected=true', 'stale raw key rejected', 'passphrase wiped', 'passphrase buffer zeroized', 'salt wiped', 'salt buffer zeroized', 'plaintext cleared', 'plaintext buffer zeroized', 'distinct_mobile_artifacts=true']],
  ['mobile-staging-config', ['staging artifact', 'EXPO_PUBLIC_API_BASE_URL', 'EXPO_PUBLIC_WS_BASE_URL', 'EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true', 'EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging', 'https://', 'wss://', 'staging', 'distinct_mobile_artifacts=true']],
]);

const forbiddenMobileProbeSummaryMarkers = [
  'development client only',
  'development client',
  'development build',
  'dev client',
  'debug client',
  'Expo Go',
  'simulator',
  'emulator',
  'remote debug',
  'node:webcrypto',
  'node webcrypto',
  'node crypto',
  'node.js crypto',
  'node crypto shim',
  'browser webcrypto',
  'global webcrypto',
  'globalThis.crypto',
  'crypto.subtle',
  'javascript fallback',
  'js fallback',
  'fallback webcrypto',
  'webcrypto fallback',
  'provider=webcrypto-fallback',
  'provider status webcrypto-fallback',
  'webcrypto-fallback',
  'native_required=false',
  'native-required false',
  'expo-crypto',
  'expo crypto',
  'placeholder',
  'mock',
  'dry-run',
  'local-only',
  'EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=false',
  'EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = false',
  'EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=development',
  'EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=local',
  'https://api.scriptureforge.com',
  'wss://api.scriptureforge.com',
];

const requiredRustProbeSummaryMarkers = new Map([
  ['rust-grpc-health', ['staging artifact', 'grpc health', 'scriptureforge.engine.ScriptureEngine', 'SERVING']],
  ['rust-metrics', ['staging artifact', 'scriptureforge_rust_engine_embedding_requests_total', 'scriptureforge_rust_engine_embedding_failures_total', 'scriptureforge_rust_engine_vector_search_requests_total', 'scriptureforge_rust_engine_vector_search_failures_total', 'Prometheus metrics', 'rust_metrics_samples_verified=true', 'rust_embedding_requests_positive=true', 'rust_vector_search_requests_positive=true']],
  ['api-rust-integration-metrics', ['staging artifact', 'Go API rust_engine vector_search success', 'scriptureforge_dependency_operations_total', 'scriptureforge_dependency_operation_duration_seconds_sum', 'api_rust_metrics_samples_verified=true', 'distinct_metrics_targets=true']],
]);

const requiredWebSmokeProbeSummaryMarkers = new Map([
  ['web-auth-browser-smoke', ['staging artifact', 'login', 'register', 'authenticated', 'https://', 'user_id=', 'organization_id=', 'distinct_web_artifacts=true']],
  ['web-journal-browser-smoke', ['staging artifact', 'journal', 'encrypted', 'save', 'load', 'plaintext absent', 'associated data', 'wrong associated data rejected', 'user_id=', 'organization_id=', 'journal_id=', 'distinct_web_artifacts=true']],
  ['web-room-browser-smoke', ['staging artifact', 'room', 'create', 'select', 'WebSocket', 'connected', 'user_id=', 'organization_id=', 'room_id=', 'distinct_web_artifacts=true']],
]);

const forbiddenWebSmokeProbeSummaryMarkers = [
  'https://api.scriptureforge.com',
  'wss://api.scriptureforge.com',
];

const forbiddenObservabilityProbeSummaryMarkers = [
  'alert silenced',
  'alert muted',
  'alert inhibited',
  'notification suppressed',
  'delivery suppressed',
  'not delivered',
  'delivery failed',
  'delivery failure',
  'send failed',
  'dry-run',
  'dry run',
];

const requiredObservabilityProbeSummaryMarkers = new Map([
  ['collector-otlp-config', ['staging artifact', 'receivers', 'otlp', '4317', '4318', 'exporters', 'service']],
  ['api-prometheus-metrics', ['staging artifact', 'scriptureforge_http_requests_total', 'scriptureforge_http_request_duration_seconds_sum', 'scriptureforge_http_requests_total{', 'status=', 'websocket_active_connections_count', 'scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped"', 'ai_inference_duration_seconds_sum', 'ai_inference_duration_seconds_count', 'scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success"', 'scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success"', 'api_metrics_samples_positive=true']],
  ['rust-prometheus-metrics', ['staging artifact', 'scriptureforge_rust_engine_embedding_requests_total', 'scriptureforge_rust_engine_embedding_failures_total', 'scriptureforge_rust_engine_vector_search_requests_total', 'scriptureforge_rust_engine_vector_search_failures_total', 'rust_metrics_samples_positive=true']],
  ['trace-backend-search', ['staging artifact', 'scriptureforge-api', 'scriptureforge-rust-engine']],
  ['log-backend-trace-correlation', ['staging artifact', 'trace_id', 'scriptureforge-api', 'scriptureforge-rust-engine', 'timestamp=', 'severity=', 'service_version', 'deployment_environment', 'tenant_id=', 'user_id=', 'role=', 'distinct_otel_artifacts=true']],
  ['dashboard-import', ['staging artifact', 'ScriptureForge', 'scriptureforge_http_requests_total', 'scriptureforge_http_request_duration_seconds_sum', 'websocket_active_connections_count', 'room_broadcast', 'ai_inference_duration_seconds', 'scriptureforge_rust_engine_', 'trace_id']],
  ['alert-rules-loaded', ['staging artifact', 'ScriptureForgeHighErrorRate', 'ScriptureForgeTrafficAbsent', 'ScriptureForgeAuthFailureSpike', 'ScriptureForgeAbuseLimitSpike', 'ScriptureForgeRouteLatencyElevated', 'ScriptureForgeDependencyFailures', 'ScriptureForgeAIInferenceLatencyElevated', 'ScriptureForgeJournalWriteFailures', 'ScriptureForgeRoomStreamFailures', 'ScriptureForgeRoomBroadcastDrops', 'ScriptureForgeRustEngineFailures', 'scriptureforge_http_requests_total', 'scriptureforge_dependency_operations_total', 'ai_inference_duration_seconds']],
  ['alert-delivery-status', ['staging artifact', 'success', 'delivered', 'test alert', 'alertmanager', 'delivery_id=', 'alertname=', 'receiver=']],
  ['telemetry-retention-policy', ['staging artifact', 'retention', '30 days', 'trace', 'logs', 'metrics', 'distinct_alert_artifacts=true']],
]);

const probeBackedEvidenceItems = new Set([
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
]);

function assertNonLocalOrPrivateTarget(target, message) {
  assert.ok(!isReservedPlaceholderTarget(target), `${message}; reserved placeholder hosts are not accepted`);
  assert.ok(!isLocalOrPrivateTarget(target), message);
}

function isReservedPlaceholderTarget(target) {
  const raw = String(target ?? '').trim();
  if (!raw) {
    return false;
  }
  const host = extractTargetHost(raw);
  if (!host) {
    return false;
  }
  const normalized = host.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  return normalized === 'example'
    || normalized.endsWith('.example')
    || normalized === 'example.com'
    || normalized.endsWith('.example.com')
    || normalized === 'example.org'
    || normalized.endsWith('.example.org')
    || normalized === 'example.net'
    || normalized.endsWith('.example.net')
    || normalized === 'test'
    || normalized.endsWith('.test')
    || normalized === 'invalid'
    || normalized.endsWith('.invalid');
}

function isLocalOrPrivateTarget(target) {
  const raw = String(target ?? '').trim();
  if (!raw) {
    return false;
  }
  const host = extractTargetHost(raw);
  if (!host) {
    return false;
  }
  const normalized = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (normalized === 'localhost') {
    return true;
  }
  if (normalized === '::' || normalized === '::1') {
    return true;
  }
  const mappedIPv4 = ipv4MappedHost(normalized);
  if (mappedIPv4) {
    return isLocalOrPrivateTarget(mappedIPv4);
  }
  if (/^f[cd][0-9a-f]*:/i.test(normalized) || /^fe[89ab][0-9a-f]*:/i.test(normalized)) {
    return true;
  }
  if (net.isIP(normalized) !== 4) {
    return false;
  }
  const parts = normalized.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [first, second] = parts;
  return first === 0
    || first === 10
    || first === 127
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

function ipv4MappedHost(host) {
  if (!host.startsWith('::ffff:')) {
    return null;
  }
  const mapped = host.slice('::ffff:'.length);
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

function extractTargetHost(target) {
  try {
    return new URL(target).hostname;
  } catch {
    // Some evidence targets are host:port pairs, such as gRPC addresses.
  }
  try {
    return new URL(`tcp://${target}`).hostname;
  } catch {
    return '';
  }
}

function assertNoLocalTarget(report, id) {
  const target = String(report.target ?? '');
  assert.ok(target.length > 0, `${id} load report must include target`);
  assertNonLocalOrPrivateTarget(target, `${id} load report target must not be local/self-test: ${target}`);
}

function validatePerformanceEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  const performanceLoadRunIDs = new Set();
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  for (const [id, target] of Object.entries(productionPerformanceTargets)) {
    if (!evidenceItems.includes(id)) {
      continue;
    }
    assertReportReleaseMatchesManifest(report, manifest, id);
    assertNoLocalTarget(report, id);
    assert.match(String(report.target), target.targetPattern, `${id} load report must use ${target.targetDescription}`);
    assert.equal(typeof report.min_rps, 'number', `${id} load report must include configured min_rps`);
    assert.equal(typeof report.max_p99_ms, 'number', `${id} load report must include configured max_p99_ms`);
    assert.equal(typeof report.production_target_rps, 'number', `${id} load report must include production_target_rps`);
    assert.equal(typeof report.production_target_p99_ms, 'number', `${id} load report must include production_target_p99_ms`);
    const productionMinDurationMS = reportNumericValue(report, 'production_min_duration_ms');
    const observedDurationMS = reportNumericValue(report, 'duration_ms');
    assert.equal(typeof report.rps, 'number', `${id} load report must include observed rps`);
    assert.equal(typeof report.p99_ms, 'number', `${id} load report must include observed p99_ms`);
    assert.deepEqual(report.threshold_failures ?? [], [], `${id} load report must have no threshold_failures`);
    assert.ok(report.production_target_rps >= target.minRPS, `${id} production_target_rps ${report.production_target_rps} is below required ${target.minRPS}`);
    assert.ok(report.production_target_p99_ms > 0 && report.production_target_p99_ms <= target.maxP99MS, `${id} production_target_p99_ms ${report.production_target_p99_ms} must be <= ${target.maxP99MS}`);
    assert.ok(productionMinDurationMS >= target.minDurationMS, `${id} production_min_duration_ms ${productionMinDurationMS} is below required ${target.minDurationMS}`);
    assert.ok(observedDurationMS >= target.minDurationMS, `${id} duration_ms ${observedDurationMS} is below required ${target.minDurationMS}`);
    assert.ok(report.min_rps >= target.minRPS, `${id} min_rps ${report.min_rps} is below required ${target.minRPS}`);
    assert.ok(report.max_p99_ms > 0 && report.max_p99_ms <= target.maxP99MS, `${id} max_p99_ms ${report.max_p99_ms} must be <= ${target.maxP99MS}`);
    assert.ok(report.rps >= target.minRPS, `${id} observed rps ${report.rps} is below required ${target.minRPS}`);
    assert.ok(report.p99_ms <= target.maxP99MS, `${id} observed p99_ms ${report.p99_ms} is above required ${target.maxP99MS}`);
    if (id === 'PERF-HTTP-001') {
      assert.equal(report.evidence_profile, 'staging_http', `${id} load report must use evidence_profile=staging_http`);
      const httpReplicaCount = reportNumericValue(report, 'http_replica_count');
      const postgresP99MS = reportNumericValue(report, 'dependency_postgres_p99_ms');
      const redisP99MS = reportNumericValue(report, 'dependency_redis_p99_ms');
      assert.ok(httpReplicaCount >= 2, `${id} http_replica_count ${httpReplicaCount} must prove at least 2 replicas`);
      assert.ok(postgresP99MS > 0 && postgresP99MS <= target.maxP99MS, `${id} dependency_postgres_p99_ms ${postgresP99MS} must be <= ${target.maxP99MS}`);
      assert.ok(redisP99MS > 0 && redisP99MS <= target.maxP99MS, `${id} dependency_redis_p99_ms ${redisP99MS} must be <= ${target.maxP99MS}`);
    }
    if (id === 'PERF-WS-001') {
      assert.equal(report.evidence_profile, 'staging_websocket', `${id} load report must use evidence_profile=staging_websocket`);
      assert.equal(report.ws_authenticated, true, `${id} report must prove ws_authenticated=true`);
      assertWebSocketPrincipalBinding(report, id);
      assertWebSocketArtifactRoomBinding(report, id);
      const wsReplicaCount = reportNumericValue(report, 'ws_replica_count');
      assert.ok(wsReplicaCount >= 2, `${id} ws_replica_count ${wsReplicaCount} must prove at least 2 replicas`);
      const productionMinWSEvents = reportNumericValue(report, 'production_min_ws_events');
      const wsExpectedEvents = reportNumericValue(report, 'ws_expected_events');
      const wsUniqueSequences = reportNumericValue(report, 'ws_unique_sequences');
      const wsMinSequence = reportNumericValue(report, 'ws_min_sequence');
      const wsMaxSequence = reportNumericValue(report, 'ws_max_sequence');
      const wsPollingLatestSequence = reportNumericValue(report, 'ws_polling_latest_sequence');
      assert.ok(productionMinWSEvents >= target.minExpectedEvents, `${id} production_min_ws_events ${productionMinWSEvents} is below required ${target.minExpectedEvents}`);
      assert.ok(wsExpectedEvents >= target.minExpectedEvents, `${id} ws_expected_events ${wsExpectedEvents} is below required ${target.minExpectedEvents}`);
      assert.equal(wsUniqueSequences, wsExpectedEvents, `${id} unique sequences must equal expected events`);
      assert.equal(wsMinSequence, 1, `${id} minimum sequence must be 1`);
      assert.equal(wsMaxSequence, wsExpectedEvents, `${id} maximum sequence must equal expected events`);
      assert.equal(wsPollingLatestSequence, wsMaxSequence, `${id} polling latest sequence must equal maximum sequence`);
      const origin = String(report.ws_origin ?? '');
      assert.match(origin, /^https:\/\//, `${id} report must include HTTPS ws_origin`);
      assertNonLocalOrPrivateTarget(origin, `${id} ws_origin must not be local/self-test: ${origin}`);
    }
    const reportReleaseCandidate = String(report.release_candidate ?? '').trim();
    const reportServiceVersion = String(report.service_version ?? '').trim();
    assert.ok(reportReleaseCandidate, `${id} report must include release_candidate`);
    assert.ok(reportServiceVersion, `${id} report must include service_version`);
    assert.ok(reportLoadRunID, `${id} report must include load_run_id`);
    performanceLoadRunIDs.add(reportLoadRunID);
    assertSummaryIncludesMarkers(id, String(report.result_summary ?? ''), [
      ...(requiredPerformanceSummaryMarkers[id] ?? []),
      `release_candidate=${reportReleaseCandidate}`,
      `service_version=${reportServiceVersion}`,
      `load_run_id=${reportLoadRunID}`,
    ]);
    assertSummaryExcludesMarkers(id, String(report.result_summary ?? ''), forbiddenPerformanceSummaryMarkers);
  }
  if (evidenceItems.includes('DATA-REDIS-001')) {
    assertReportReleaseMatchesManifest(report, manifest, 'DATA-REDIS-001');
    assert.ok(evidenceItems.includes('PERF-WS-001'), 'DATA-REDIS-001 load evidence must be paired with PERF-WS-001');
    const wsRoomID = String(report.ws_room_id ?? '').trim();
    assert.match(wsRoomID, /\S/, 'DATA-REDIS-001 report must include ws_room_id');
    assertWebSocketPrincipalBinding(report, 'DATA-REDIS-001');
    assertWebSocketArtifactRoomBinding(report, 'DATA-REDIS-001');
    assert.equal(report.ws_reconnect_sequence_continues, true, 'DATA-REDIS-001 report must prove ws_reconnect_sequence_continues=true');
    assert.equal(report.ws_sequence_contiguous, true, 'DATA-REDIS-001 report must prove ws_sequence_contiguous=true');
    assert.equal(typeof report.ws_expected_events, 'number', 'DATA-REDIS-001 report must include ws_expected_events');
    assert.equal(typeof report.ws_unique_sequences, 'number', 'DATA-REDIS-001 report must include ws_unique_sequences');
    assert.equal(typeof report.ws_min_sequence, 'number', 'DATA-REDIS-001 report must include ws_min_sequence');
    assert.equal(typeof report.ws_max_sequence, 'number', 'DATA-REDIS-001 report must include ws_max_sequence');
    assert.equal(typeof report.ws_polling_latest_sequence, 'number', 'DATA-REDIS-001 report must include ws_polling_latest_sequence');
    assert.ok(report.ws_expected_events > 0, 'DATA-REDIS-001 ws_expected_events must be positive');
    assert.equal(report.ws_unique_sequences, report.ws_expected_events, 'DATA-REDIS-001 unique sequences must equal expected events');
    assert.equal(report.ws_min_sequence, 1, 'DATA-REDIS-001 minimum sequence must be 1');
    assert.equal(report.ws_max_sequence, report.ws_expected_events, 'DATA-REDIS-001 maximum sequence must equal expected events');
    assert.equal(report.ws_polling_latest_sequence, report.ws_max_sequence, 'DATA-REDIS-001 polling latest sequence must equal maximum sequence');
    const roomBroadcastDrops = reportNumericValue(report, 'room_broadcast_drops');
    assert.equal(roomBroadcastDrops, 0, 'DATA-REDIS-001 room_broadcast_drops must equal 0');
    assertSummaryIncludesMarkers('DATA-REDIS-001 polling fallback', String(report.result_summary ?? ''), [
      `ws_polling_latest_sequence=${report.ws_max_sequence}`,
    ]);
    assertSummaryIncludesMarkers('DATA-REDIS-001 room binding', String(report.result_summary ?? ''), [
      `ws_room_id=${wsRoomID}`,
    ]);
    assertSummaryIncludesMarkers('DATA-REDIS-001', String(report.result_summary ?? ''), [
      ...requiredPerformanceSummaryMarkers['DATA-REDIS-001'],
      `release_candidate=${String(report.release_candidate ?? '').trim()}`,
      `service_version=${String(report.service_version ?? '').trim()}`,
      `load_run_id=${reportLoadRunID}`,
    ]);
    performanceLoadRunIDs.add(reportLoadRunID);
  }
  assertPerformanceLoadRunMatchesManifest(manifest, performanceLoadRunIDs);
  if (evidenceItems.includes('PERF-HTTP-001')) {
    const httpReplicaArtifactURL = String(report.http_replica_artifact_url ?? '');
    assert.match(httpReplicaArtifactURL, /^https:\/\//, 'PERF-HTTP-001 report must include HTTPS http_replica_artifact_url');
    assertNonLocalOrPrivateTarget(httpReplicaArtifactURL, `PERF-HTTP-001 http_replica_artifact_url must not be local/self-test: ${httpReplicaArtifactURL}`);
    const dependencyTelemetryArtifactURL = String(report.dependency_telemetry_artifact_url ?? '');
    assert.match(dependencyTelemetryArtifactURL, /^https:\/\//, 'PERF-HTTP-001 report must include HTTPS dependency_telemetry_artifact_url');
    assertNonLocalOrPrivateTarget(dependencyTelemetryArtifactURL, `PERF-HTTP-001 dependency_telemetry_artifact_url must not be local/self-test: ${dependencyTelemetryArtifactURL}`);
    assertDistinctReportURLs('PERF-HTTP-001', [
      ['http_replica_artifact_url', httpReplicaArtifactURL],
      ['dependency_telemetry_artifact_url', dependencyTelemetryArtifactURL],
    ]);
  }
  if (evidenceItems.includes('PERF-WS-001')) {
    assert.match(String(report.ws_room_id ?? ''), /\S/, 'PERF-WS-001 report must include ws_room_id');
    assert.equal(report.ws_reconnect_sequence_continues, true, 'PERF-WS-001 report must prove ws_reconnect_sequence_continues=true');
    const replicaArtifactURL = String(report.ws_replica_artifact_url ?? '');
    assert.match(replicaArtifactURL, /^https:\/\//, 'PERF-WS-001 report must include HTTPS ws_replica_artifact_url');
    assertNonLocalOrPrivateTarget(replicaArtifactURL, `PERF-WS-001 ws_replica_artifact_url must not be local/self-test: ${replicaArtifactURL}`);
    const reconnectArtifactURL = String(report.ws_reconnect_artifact_url ?? '');
    assert.match(reconnectArtifactURL, /^https:\/\//, 'PERF-WS-001 report must include HTTPS ws_reconnect_artifact_url');
    assertNonLocalOrPrivateTarget(reconnectArtifactURL, `PERF-WS-001 ws_reconnect_artifact_url must not be local/self-test: ${reconnectArtifactURL}`);
    const pollingArtifactURL = String(report.ws_polling_artifact_url ?? '');
    assert.match(pollingArtifactURL, /^https:\/\//, 'PERF-WS-001 report must include HTTPS ws_polling_artifact_url');
    assertNonLocalOrPrivateTarget(pollingArtifactURL, `PERF-WS-001 ws_polling_artifact_url must not be local/self-test: ${pollingArtifactURL}`);
    assertDistinctReportURLs('PERF-WS-001', [
      ['ws_replica_artifact_url', replicaArtifactURL],
      ['ws_reconnect_artifact_url', reconnectArtifactURL],
      ['ws_polling_artifact_url', pollingArtifactURL],
      ['redis_telemetry_artifact_url', String(report.redis_telemetry_artifact_url ?? '')],
    ]);
  }
  if (evidenceItems.includes('DATA-REDIS-001')) {
    const redisTelemetryArtifactURL = String(report.redis_telemetry_artifact_url ?? '');
    assert.match(redisTelemetryArtifactURL, /^https:\/\//, 'DATA-REDIS-001 report must include HTTPS redis_telemetry_artifact_url');
    assertNonLocalOrPrivateTarget(redisTelemetryArtifactURL, `DATA-REDIS-001 redis_telemetry_artifact_url must not be local/self-test: ${redisTelemetryArtifactURL}`);
  }
}

function assertWebSocketArtifactRoomBinding(report, id) {
  const wsRoomID = String(report.ws_room_id ?? '').trim();
  assert.match(wsRoomID, /\S/, `${id} report must include ws_room_id`);
  for (const field of ['ws_reconnect_room_id', 'ws_polling_room_id', 'redis_telemetry_room_id']) {
    const value = String(report[field] ?? '').trim();
    assert.match(value, /\S/, `${id} report must include ${field}`);
    assert.equal(value, wsRoomID, `${id} ${field} must match ws_room_id`);
    assertSummaryIncludesMarkers(`${id} ${field} room binding`, String(report.result_summary ?? ''), [
      `${field}=${wsRoomID}`,
    ]);
  }
}

function assertWebSocketPrincipalBinding(report, id) {
  const wsUserID = String(report.ws_user_id ?? '').trim();
  const wsOrganizationID = String(report.ws_organization_id ?? '').trim();
  assert.match(wsUserID, tenantResourceIDPattern, `${id} report must include structured ws_user_id`);
  assert.match(wsOrganizationID, tenantResourceIDPattern, `${id} report must include structured ws_organization_id`);
  assert.notEqual(wsUserID, wsOrganizationID, `${id} ws_user_id and ws_organization_id must be distinct`);
  assertSummaryIncludesMarkers(`${id} principal binding`, String(report.result_summary ?? ''), [
    `ws_user_id=${wsUserID}`,
    `ws_organization_id=${wsOrganizationID}`,
  ]);
}

function assertPerformanceLoadRunMatchesManifest(manifest, incomingLoadRunIDs) {
  if (incomingLoadRunIDs.size === 0) {
    return;
  }
  for (const id of performanceEvidenceItemIDs) {
    const item = manifest.items?.find((candidate) => candidate.id === id);
    if (!item || item.status !== 'passed' || !Array.isArray(item.evidence)) {
      continue;
    }
    for (const evidence of item.evidence) {
      const existingLoadRunID = summaryMarkerValue(String(evidence.result_summary ?? ''), 'load_run_id');
      if (existingLoadRunID) {
        incomingLoadRunIDs.add(existingLoadRunID);
      }
    }
  }
  assert.equal(
    incomingLoadRunIDs.size,
    1,
    'performance evidence load_run_id values must match across PERF-HTTP-001, PERF-WS-001, and DATA-REDIS-001',
  );
}

function assertReportLoadRunMatchesManifest(manifest, report) {
  const reportLoadRunIDs = collectReportLoadRunIDs(report);
  if (reportLoadRunIDs.size === 0) {
    return;
  }
  const loadRunIDs = new Set(reportLoadRunIDs);
  for (const item of manifest.items ?? []) {
    if (item.status !== 'passed' || !Array.isArray(item.evidence)) {
      continue;
    }
    for (const evidence of item.evidence) {
      const existingLoadRunID = summaryMarkerValue(String(evidence.result_summary ?? ''), 'load_run_id');
      if (existingLoadRunID) {
        loadRunIDs.add(existingLoadRunID);
      }
    }
  }
  assert.equal(
    loadRunIDs.size,
    1,
    'staging evidence load_run_id values must match across all recorded release evidence',
  );
}

function collectReportLoadRunIDs(report) {
  const loadRunIDs = new Set();
  const topLevelLoadRunID = String(report.load_run_id ?? '').trim();
  if (topLevelLoadRunID) {
    loadRunIDs.add(topLevelLoadRunID);
  }
  const summaries = [
    report.result_summary,
    report.config_artifact_summary,
    ...(Array.isArray(report.probes) ? report.probes.map((probe) => probe.result_summary) : []),
  ];
  for (const summary of summaries) {
    const loadRunID = summaryMarkerValue(String(summary ?? ''), 'load_run_id');
    if (loadRunID) {
      loadRunIDs.add(loadRunID);
    }
  }
  return loadRunIDs;
}

function reportNumericValue(report, key) {
  if (typeof report[key] === 'number') {
    return report[key];
  }
  const summary = String(report.result_summary ?? '');
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = summary.match(new RegExp(`(?:^|\\s|;)${escaped}=(-?\\d+(?:\\.\\d+)?)\\b`));
  assert.ok(match, `load report must include ${key}`);
  return Number(match[1]);
}

function summaryMarkerValue(summary, key) {
  const pattern = new RegExp(`(?:^|[\\s,;])${key}=([^\\s,;]+)`, 'i');
  return pattern.exec(String(summary ?? ''))?.[1] ?? '';
}

function assertProbeLoadRunBinding(probeName, summary, reportLoadRunID, probeLoadRunIDs) {
  const probeLoadRunID = summaryMarkerValue(summary, 'load_run_id');
  assert.ok(probeLoadRunID, `${probeName} result_summary must include verified marker load_run_id=`);
  if (reportLoadRunID) {
    assert.equal(
      probeLoadRunID,
      reportLoadRunID,
      `${probeName} result_summary load_run_id must match report load_run_id`,
    );
  }
  probeLoadRunIDs.add(probeLoadRunID);
  return `load_run_id=${probeLoadRunID}`;
}

function assertSingleProbeLoadRun(evidenceID, probeLoadRunIDs) {
  assert.equal(
    probeLoadRunIDs.size,
    1,
    `${evidenceID} probe result_summary load_run_id values must all match`,
  );
}

function validateTLSEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('DEPLOY-TLS-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'DEPLOY-TLS-001');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'DEPLOY-TLS-001 report must include load_run_id');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
    `load_run_id=${reportLoadRunID}`,
  ];
  for (const [field, label] of [
    ['dns_artifact_url', 'DNS'],
    ['acm_artifact_url', 'ACM'],
  ]) {
    const artifactURL = String(report[field] ?? '');
    assert.match(artifactURL, /^https:\/\//, `DEPLOY-TLS-001 report must include HTTPS ${field}`);
    assertNonLocalOrPrivateTarget(artifactURL, `DEPLOY-TLS-001 ${label} artifact must not be local/self-test: ${artifactURL}`);
  }
  assertDistinctReportURLs('DEPLOY-TLS-001', [
    ['dns_artifact_url', String(report.dns_artifact_url ?? '')],
    ['acm_artifact_url', String(report.acm_artifact_url ?? '')],
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const probesByName = new Map(probes.map((probe) => [probe.name, probe]));
  const probeLoadRunIDs = new Set();
  const apiTarget = String(report.api_target ?? '');
  const webTarget = String(report.web_target ?? '');
  assert.ok(apiTarget || webTarget, 'DEPLOY-TLS-001 report must include api_target or web_target');
  if (apiTarget) {
    assert.match(apiTarget, /^https:\/\//, 'DEPLOY-TLS-001 api_target must use HTTPS');
    assertNonLocalOrPrivateTarget(apiTarget, `DEPLOY-TLS-001 api_target must not be local/self-test: ${apiTarget}`);
    assertHTTPProbe(probesByName, 'api-live', `${apiTarget}/live`, 200, reportReleaseMarkers);
    assertHTTPProbe(probesByName, 'api-ready', `${apiTarget}/ready`, 200, reportReleaseMarkers);
    assertTLSProbe(probesByName, 'api-tls', apiTarget, reportReleaseMarkers);
    assertRedirectProbe(probesByName, 'api-http-redirect', reportReleaseMarkers);
  }
  if (webTarget) {
    assert.match(webTarget, /^https:\/\//, 'DEPLOY-TLS-001 web_target must use HTTPS');
    assertNonLocalOrPrivateTarget(webTarget, `DEPLOY-TLS-001 web_target must not be local/self-test: ${webTarget}`);
    assertHTTPProbe(probesByName, 'web-root', webTarget, 200, reportReleaseMarkers);
    assertTLSProbe(probesByName, 'web-tls', webTarget, reportReleaseMarkers);
    assertRedirectProbe(probesByName, 'web-http-redirect', reportReleaseMarkers);
  }
  for (const probe of probes) {
    const summary = String(probe.result_summary ?? '');
    if (summary.includes('release_candidate=') || summary.includes('load_run_id=')) {
      assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    }
  }
  assertSingleProbeLoadRun('DEPLOY-TLS-001', probeLoadRunIDs);
}

function assertHTTPProbe(probesByName, name, expectedTarget, expectedStatus, extraMarkers = []) {
  const probe = probesByName.get(name);
  assert.ok(probe, `DEPLOY-TLS-001 report must include ${name} probe`);
  assert.equal(probe.passed, true, `${name} must pass`);
  assert.equal(probe.status_code, expectedStatus, `${name} must return HTTP ${expectedStatus}`);
  assert.equal(String(probe.target ?? ''), expectedTarget, `${name} target must match ${expectedTarget}`);
  assertSummaryIncludesMarkers(name, String(probe.result_summary ?? ''), [...(requiredStagingProbeSummaryMarkers.get(name) ?? []), ...extraMarkers]);
}

function assertTLSProbe(probesByName, name, expectedTarget, extraMarkers = []) {
	const probe = probesByName.get(name);
	assert.ok(probe, `DEPLOY-TLS-001 report must include ${name} probe`);
	assert.equal(probe.passed, true, `${name} must pass`);
	assert.equal(String(probe.target ?? ''), expectedTarget, `${name} target must match ${expectedTarget}`);
	assert.ok(String(probe.tls_version ?? '').trim(), `${name} must include tls_version`);
	assert.match(String(probe.cert_not_after ?? ''), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, `${name} must include cert_not_after`);
	const expectedHostname = new URL(expectedTarget).hostname.toLowerCase();
	const certHostname = String(probe.cert_hostname ?? '').trim().toLowerCase();
	const certIssuer = String(probe.cert_issuer ?? '').trim();
	assert.equal(certHostname, expectedHostname, `${name} must include cert_hostname matching ${expectedHostname}`);
	assert.match(certIssuer, /^[A-Za-z0-9][A-Za-z0-9._:-]*$/, `${name} must include structured cert_issuer`);
	assertSummaryIncludesMarkers(name, String(probe.result_summary ?? ''), [`cert_hostname=${certHostname}`, `cert_issuer=${certIssuer}`]);
	assertSummaryIncludesMarkers(name, String(probe.result_summary ?? ''), [...(requiredStagingProbeSummaryMarkers.get(name) ?? []), ...extraMarkers]);
}

function assertRedirectProbe(probesByName, name, extraMarkers = []) {
  const probe = probesByName.get(name);
  assert.ok(probe, `DEPLOY-TLS-001 report must include ${name} probe`);
  assert.equal(probe.passed, true, `${name} must pass`);
  assert.ok(probe.status_code >= 300 && probe.status_code < 400, `${name} must observe an HTTP redirect`);
  assert.match(String(probe.target ?? ''), /^http:\/\//, `${name} target must be the HTTP endpoint`);
  assertNonLocalOrPrivateTarget(String(probe.target ?? ''), `${name} target must not be local/self-test: ${probe.target}`);
  assert.match(String(probe.redirect_to ?? ''), /^https:\/\//, `${name} must redirect to HTTPS`);
  assertSummaryIncludesMarkers(name, String(probe.result_summary ?? ''), [...(requiredStagingProbeSummaryMarkers.get(name) ?? []), ...extraMarkers]);
}

function validateCIEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('SRC-CI-001')) {
    return;
  }
  assert.match(String(report.commit_sha ?? ''), /^[a-fA-F0-9]{40}$/, 'SRC-CI-001 report must include full commit_sha');
  const manifestReleaseCandidate = String(manifest.release_candidate ?? '').trim();
  if (manifestReleaseCandidate) {
    assert.equal(
      String(report.commit_sha ?? '').trim().toLowerCase(),
      manifestReleaseCandidate.toLowerCase(),
      'SRC-CI-001 report commit_sha must match manifest release_candidate',
    );
  }
  assert.ok(String(report.workflow_name ?? '').trim(), 'SRC-CI-001 report must include workflow_name');
  assert.match(String(report.repository ?? ''), /^[^/\s]+\/[^/\s]+$/, 'SRC-CI-001 report must include GitHub repository owner/name');
  assert.match(String(report.ref ?? ''), /^refs\/(heads|tags|pull)\/.+/, 'SRC-CI-001 report must include full GitHub ref');
  assert.ok(String(report.ref_name ?? '').trim(), 'SRC-CI-001 report must include ref_name');
  assert.ok(String(report.event_name ?? '').trim(), 'SRC-CI-001 report must include event_name');
  assert.equal(report.source_control_status, 'clean', 'SRC-CI-001 report must include source_control_status=clean');
  assert.equal(report.release_evidence_scope, 'exact-github-sha-required-gates', 'SRC-CI-001 report must include release_evidence_scope=exact-github-sha-required-gates');
  const runURL = String(report.ci_run_url ?? '');
  assert.match(runURL, /^https:\/\/github\.com\/[^/]+\/[^/]+\/actions\/runs\/\d+/, 'SRC-CI-001 report must include GitHub Actions ci_run_url');
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const releaseRun = probes.find((probe) => probe.name === 'github-actions-release-run');
  assert.ok(releaseRun, 'SRC-CI-001 report must include github-actions-release-run probe');
  assert.equal(releaseRun.passed, true, 'github-actions-release-run must pass');
  const releaseRunTarget = String(releaseRun.target ?? '');
  assert.match(releaseRunTarget, /^https:\/\//, 'github-actions-release-run target must be an uploaded HTTPS ci-release-evidence artifact URL');
  assertNonLocalOrPrivateTarget(releaseRunTarget, `github-actions-release-run target must not be local/self-test: ${releaseRunTarget}`);
  assert.ok(!isReservedPlaceholderTarget(releaseRunTarget), 'github-actions-release-run target must not use reserved placeholder hosts');
  assert.match(releaseRunTarget, /ci-release-evidence/i, 'github-actions-release-run target must reference uploaded ci-release-evidence artifact');
  assert.equal(String(releaseRun.run_url ?? ''), runURL, 'github-actions-release-run probe run_url must match ci_run_url');
  assert.equal(String(releaseRun.repository ?? ''), report.repository, 'github-actions-release-run probe repository must match report repository');
  assert.equal(String(releaseRun.ref ?? ''), report.ref, 'github-actions-release-run probe ref must match report ref');
  assert.equal(String(releaseRun.ref_name ?? ''), report.ref_name, 'github-actions-release-run probe ref_name must match report ref_name');
  assert.equal(String(releaseRun.event_name ?? ''), report.event_name, 'github-actions-release-run probe event_name must match report event_name');
  assert.equal(String(releaseRun.source_control_status ?? ''), 'clean', 'github-actions-release-run probe must include source_control_status=clean');
  assert.equal(String(releaseRun.release_evidence_scope ?? ''), 'exact-github-sha-required-gates', 'github-actions-release-run probe must include release_evidence_scope=exact-github-sha-required-gates');
  assertSummaryIncludesMarkers('SRC-CI-001', String(releaseRun.result_summary ?? ''), [
    'proof markers:',
    ...ciReleaseEvidenceProofMarkers,
  ]);
}

function assertReportReleaseMatchesManifest(report, manifest, evidenceID) {
  const manifestReleaseCandidate = String(manifest.release_candidate ?? '').trim();
  if (!manifestReleaseCandidate) {
    return;
  }
  const reportReleaseCandidate = String(report.release_candidate ?? '').trim();
  assert.ok(reportReleaseCandidate, `${evidenceID} report must include release_candidate`);
  assert.equal(
    reportReleaseCandidate,
    manifestReleaseCandidate,
    `${evidenceID} report release_candidate must match manifest release_candidate`,
  );
  const reportServiceVersion = String(report.service_version ?? '').trim();
  assert.ok(reportServiceVersion, `${evidenceID} report must include service_version`);
  assert.ok(
    reportServiceVersion.includes(manifestReleaseCandidate),
    `${evidenceID} report service_version must include manifest release_candidate`,
  );
}

function validateKubernetesEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('DEPLOY-K8S-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'DEPLOY-K8S-001');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  if (String(manifest.release_candidate ?? '').trim()) {
    assert.ok(reportLoadRunID, 'DEPLOY-K8S-001 report must include load_run_id');
  }
  const probeLoadRunIDs = new Set();
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const probesByName = new Map(probes.map((probe) => [probe.name, probe]));
  const artifactTargets = [];
  for (const name of ['kubernetes-rollout-status', 'kubernetes-workload-resources']) {
    const probe = probesByName.get(name);
    assert.ok(probe, `DEPLOY-K8S-001 report must include ${name} probe`);
    assert.equal(probe.passed, true, `${name} must pass`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https:\/\//, `${name} target must be an HTTPS artifact URL`);
    assertNonLocalOrPrivateTarget(target, `${name} target must not be local/self-test: ${target}`);
    artifactTargets.push([name, target]);
    const summary = String(probe.result_summary ?? '');
    const probeLoadRunMarker = assertProbeLoadRunBinding(name, summary, reportLoadRunID, probeLoadRunIDs);
    assertSummaryIncludesMarkers(name, summary, [...(requiredKubernetesProbeSummaryMarkers.get(name) ?? []), probeLoadRunMarker]);
    assertSummaryExcludesMarkers(name, summary, forbiddenDeploymentSummaryMarkers);
    if (name === 'kubernetes-workload-resources') {
      const digestCount = countImmutableImageDigests(summary);
      assert.ok(
        digestCount >= 3,
        `kubernetes-workload-resources result_summary must include at least 3 immutable image digests, found ${digestCount}`,
      );
      assertKubernetesWorkloadImageDigests(summary, 'kubernetes-workload-resources result_summary');
      assertKubernetesWorkloadStructuredImageDigests(probe, summary);
    }
  }
  assertDistinctReportURLs('DEPLOY-K8S-001', artifactTargets);
  assertSingleProbeLoadRun('DEPLOY-K8S-001', probeLoadRunIDs);
}

function countImmutableImageDigests(summary) {
  return new Set(String(summary ?? '').match(immutableImageDigestPattern) ?? []).size;
}

function assertKubernetesWorkloadImageDigests(summary, label) {
  for (const [workload, pattern] of kubernetesWorkloadImageDigestPatterns) {
    assert.match(
      String(summary ?? ''),
      pattern,
      `${label} must include immutable image digest bound to ${workload}`,
    );
  }
}

function assertKubernetesWorkloadStructuredImageDigests(probe, summary) {
  const concreteImageDigests = Number(probe?.concrete_image_digests);
  const workloadImageDigests = Number(probe?.workload_image_digests);
  assert.equal(
    Number.isInteger(concreteImageDigests) && concreteImageDigests >= 3,
    true,
    'kubernetes-workload-resources probe must include structured concrete_image_digests >= 3',
  );
  assert.equal(
    workloadImageDigests,
    kubernetesWorkloadImageDigestPatterns.size,
    'kubernetes-workload-resources probe must include structured workload_image_digests=3',
  );
  const imageDigests = probe?.image_digests;
  assert.equal(
    imageDigests && typeof imageDigests === 'object' && !Array.isArray(imageDigests),
    true,
    'kubernetes-workload-resources probe must include structured image_digests',
  );
  for (const [workload] of kubernetesWorkloadImageDigestPatterns) {
    const digest = String(imageDigests[workload] ?? '').trim().toLowerCase();
    assert.match(
      digest,
      /^sha256:[a-f0-9]{64}$/,
      `kubernetes-workload-resources structured image_digests.${workload} must be an immutable sha256 digest`,
    );
    assert.ok(
      String(summary ?? '').toLowerCase().includes(`${workload}@${digest}`),
      `kubernetes-workload-resources result_summary must include structured image digest marker ${workload}@${digest}`,
    );
  }
}

function summaryIncludesAll(summary, markers) {
  const lowered = summary.toLowerCase();
  return markers.every((marker) => lowered.includes(marker.toLowerCase()));
}

function assertSummaryIncludesMarkers(probeName, summary, markers) {
  for (const marker of markers) {
    assert.ok(
      summary.toLowerCase().includes(marker.toLowerCase()),
      `${probeName} result_summary must include verified marker ${marker}`,
    );
  }
}

function assertSummaryExcludesMarkers(probeName, summary, markers) {
  for (const marker of markers) {
    assert.ok(
      !summary.toLowerCase().includes(marker.toLowerCase()),
      `${probeName} result_summary must not include forbidden marker ${marker}`,
    );
  }
}

function assertDistinctReportURLs(scope, entries) {
  const seen = new Map();
  for (const [name, value] of entries) {
    const normalized = canonicalReportURL(value);
    if (!normalized) {
      continue;
    }
    const previous = seen.get(normalized);
    assert.ok(!previous, `${scope} ${name} must be a distinct artifact URL from ${previous}`);
    seen.set(normalized, name);
  }
}

function canonicalReportURL(value) {
  const raw = String(value ?? '').trim();
  if (!raw) {
    return '';
  }
  try {
    const parsed = new URL(raw);
    parsed.protocol = parsed.protocol.toLowerCase();
    parsed.hostname = parsed.hostname.toLowerCase();
    if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) {
      parsed.port = '';
    }
    parsed.hash = '';
    const searchParams = new URLSearchParams(parsed.searchParams);
    searchParams.sort();
    parsed.search = searchParams.toString();
    return parsed.toString();
  } catch {
    return raw.toLowerCase();
  }
}

function assertDistinctReportHosts(scope, entries) {
  const seen = new Map();
  for (const [name, value] of entries) {
    const normalized = String(value ?? '').trim();
    if (!normalized) {
      continue;
    }
    let host;
    try {
      host = canonicalReportHost(new URL(normalized).hostname);
    } catch {
      host = canonicalReportHost(normalized);
    }
    const previous = seen.get(host);
    assert.ok(!previous, `${scope} ${name} must use a distinct host from ${previous}`);
    seen.set(host, name);
  }
}

function canonicalReportHost(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.+$/g, '');
}

function extractFirstMatch(value, pattern) {
  const match = String(value ?? '').match(pattern);
  return match?.[1] ?? '';
}

function targetIncludesTraceID(target, traceID) {
  const expected = String(traceID ?? '').trim().toLowerCase();
  if (!expected) {
    return false;
  }
  const rawTarget = String(target ?? '');
  const candidates = [rawTarget];
  try {
    candidates.push(decodeURIComponent(rawTarget));
  } catch {
    // Keep validating against the raw target if percent-decoding fails.
  }
  try {
    const parsed = new URL(rawTarget);
    candidates.push(parsed.search);
    for (const value of parsed.searchParams.values()) {
      candidates.push(value);
    }
  } catch {
    // URL shape is validated separately by the caller.
  }
  return candidates.some((candidate) => String(candidate).toLowerCase().includes(expected));
}

function validateTerraformEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('DEPLOY-TF-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'DEPLOY-TF-001');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  if (String(manifest.release_candidate ?? '').trim()) {
    assert.ok(reportLoadRunID, 'DEPLOY-TF-001 report must include load_run_id');
  }
  const probeLoadRunIDs = new Set();
  const requiredProbes = new Set([
    'terraform-remote-backend-init',
    'terraform-staging-plan',
    'terraform-staging-apply-or-approval',
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, requiredProbes.size, 'DEPLOY-TF-001 report must include exactly the required Terraform probes');
  const terraformArtifactTargets = [];
  for (const probe of probes) {
    assert.ok(requiredProbes.delete(probe.name), `DEPLOY-TF-001 report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 200, `${probe.name} must return HTTP 200`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS artifact URL`);
    assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
    terraformArtifactTargets.push([`${probe.name} target`, target]);
    const summary = String(probe.result_summary ?? '');
    const probeLoadRunMarker = assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    assertSummaryExcludesMarkers(probe.name, summary, forbiddenDeploymentSummaryMarkers);
    if (probe.name === 'terraform-staging-apply-or-approval') {
      const matchedSet = terraformApplyOrApprovalSummaryMarkerSets.find((markers) => summaryIncludesAll(summary, markers));
      assert.ok(matchedSet, 'terraform-staging-apply-or-approval result_summary must include apply-complete or deployment-approval markers');
      assertSummaryIncludesMarkers(probe.name, summary, [probeLoadRunMarker]);
      if (summaryIncludesAll(summary, ['deployment approval', 'approved', 'DEPLOY-TF-001'])) {
        assert.match(summary, terraformApprovalChangeTicketPattern, 'terraform-staging-apply-or-approval deployment approval summary must include change_ticket=<ticket-id>');
        const changeTicket = String(probe.change_ticket ?? '').trim();
        assert.match(changeTicket, /^[A-Z][A-Z0-9]+-\d+$/, 'terraform-staging-apply-or-approval deployment approval report must include structured change_ticket');
        assert.ok(
          summary.toLowerCase().includes(`change_ticket=${changeTicket}`.toLowerCase()),
          'terraform-staging-apply-or-approval deployment approval summary must match structured change_ticket',
        );
      }
    } else {
      assertSummaryIncludesMarkers(probe.name, summary, [...(requiredTerraformProbeSummaryMarkers.get(probe.name) ?? []), probeLoadRunMarker]);
    }
  }
  assertDistinctReportURLs('DEPLOY-TF-001', terraformArtifactTargets);
  assertSingleProbeLoadRun('DEPLOY-TF-001', probeLoadRunIDs);
  assert.equal(requiredProbes.size, 0, `DEPLOY-TF-001 report missing probes: ${[...requiredProbes].join(', ')}`);
}

function validateWebClientEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('CLIENT-WEB-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'CLIENT-WEB-001');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'CLIENT-WEB-001 report must include load_run_id');
  const reportWebUserID = String(report.web_user_id ?? '').trim();
  const reportWebOrganizationID = String(report.web_organization_id ?? '').trim();
  const reportWebJournalID = String(report.web_journal_id ?? '').trim();
  const reportWebRoomID = String(report.web_room_id ?? '').trim();
  assert.match(reportWebUserID, tenantResourceIDPattern, 'CLIENT-WEB-001 report must include structured web_user_id');
  assert.match(reportWebOrganizationID, tenantResourceIDPattern, 'CLIENT-WEB-001 report must include structured web_organization_id');
  assert.match(reportWebJournalID, tenantResourceIDPattern, 'CLIENT-WEB-001 report must include structured web_journal_id');
  assert.match(reportWebRoomID, tenantResourceIDPattern, 'CLIENT-WEB-001 report must include structured web_room_id');
  const reportReleaseMarkers = [];
  if (String(report.release_candidate ?? '').trim() || String(report.service_version ?? '').trim()) {
    reportReleaseMarkers.push(
      `release_candidate=${String(report.release_candidate ?? '').trim()}`,
      `service_version=${String(report.service_version ?? '').trim()}`,
      `load_run_id=${reportLoadRunID}`,
    );
  }
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const probeLoadRunIDs = new Set();
  const webRoot = probes.find((probe) => probe.name === 'web-root');
  assert.ok(webRoot, 'CLIENT-WEB-001 report must include web-root probe');
  assert.equal(webRoot.passed, true, 'web-root must pass');
  assert.equal(webRoot.status_code, 200, 'web-root must return HTTP 200');
  const webTarget = String(report.web_target ?? '');
  assert.match(webTarget, /^https:\/\//, 'CLIENT-WEB-001 report must include HTTPS web_target');
  assertNonLocalOrPrivateTarget(webTarget, `CLIENT-WEB-001 web_target must not be local/self-test: ${webTarget}`);
  const probesByName = new Map(probes.map((probe) => [probe.name, probe]));
  assertTLSProbe(probesByName, 'web-tls', webTarget);
  assertRedirectProbe(probesByName, 'web-http-redirect');
  for (const [field, label] of [
    ['web_auth_smoke_url', 'auth browser smoke'],
    ['web_journal_smoke_url', 'journal browser smoke'],
    ['web_room_smoke_url', 'room browser smoke'],
  ]) {
    const artifactURL = String(report[field] ?? '');
    assert.match(artifactURL, /^https:\/\//, `CLIENT-WEB-001 report must include HTTPS ${field}`);
    assertNonLocalOrPrivateTarget(artifactURL, `CLIENT-WEB-001 ${label} artifact must not be local/self-test: ${artifactURL}`);
  }
  assertDistinctReportURLs('CLIENT-WEB-001', [
    ['web_auth_smoke_url', report.web_auth_smoke_url],
    ['web_journal_smoke_url', report.web_journal_smoke_url],
    ['web_room_smoke_url', report.web_room_smoke_url],
  ]);
  const smokeProbeTargets = new Map([
    ['web-auth-browser-smoke', String(report.web_auth_smoke_url ?? '')],
    ['web-journal-browser-smoke', String(report.web_journal_smoke_url ?? '')],
    ['web-room-browser-smoke', String(report.web_room_smoke_url ?? '')],
  ]);
  for (const [probeName, expectedTarget] of smokeProbeTargets) {
    const probe = probesByName.get(probeName);
    assert.ok(probe, `CLIENT-WEB-001 report must include ${probeName} probe`);
    assert.equal(probe.passed, true, `${probeName} must pass`);
    assert.equal(probe.status_code, 200, `${probeName} must return HTTP 200`);
    assert.equal(String(probe.target ?? ''), expectedTarget, `${probeName} target must match its smoke artifact URL`);
    assertSummaryExcludesMarkers(probeName, String(probe.result_summary ?? ''), forbiddenWebSmokeProbeSummaryMarkers);
    const summary = String(probe.result_summary ?? '');
    assertProbeLoadRunBinding(probeName, summary, reportLoadRunID, probeLoadRunIDs);
    assertSummaryIncludesMarkers(probeName, summary, [...(requiredWebSmokeProbeSummaryMarkers.get(probeName) ?? []), ...reportReleaseMarkers]);
    const userID = String(probe.user_id ?? '').trim();
    const organizationID = String(probe.organization_id ?? '').trim();
    assert.match(userID, tenantResourceIDPattern, `${probeName} probe must include structured user_id`);
    assert.match(organizationID, tenantResourceIDPattern, `${probeName} probe must include structured organization_id`);
    assertSummaryIncludesMarkers(probeName, String(probe.result_summary ?? ''), [`user_id=${userID}`, `organization_id=${organizationID}`]);
    assert.equal(userID, reportWebUserID, `${probeName} user_id must match report web_user_id`);
    assert.equal(organizationID, reportWebOrganizationID, `${probeName} organization_id must match report web_organization_id`);
    if (probeName === 'web-journal-browser-smoke') {
      const journalID = String(probe.journal_id ?? '').trim();
      assert.match(journalID, tenantResourceIDPattern, `${probeName} probe must include structured journal_id`);
      assertSummaryIncludesMarkers(probeName, String(probe.result_summary ?? ''), [`journal_id=${journalID}`]);
      assert.equal(journalID, reportWebJournalID, `${probeName} journal_id must match report web_journal_id`);
    }
    if (probeName === 'web-room-browser-smoke') {
      const roomID = String(probe.room_id ?? '').trim();
      assert.match(roomID, tenantResourceIDPattern, `${probeName} probe must include structured room_id`);
      assertSummaryIncludesMarkers(probeName, String(probe.result_summary ?? ''), [`room_id=${roomID}`]);
      assert.equal(roomID, reportWebRoomID, `${probeName} room_id must match report web_room_id`);
    }
  }
  const authProbe = probesByName.get('web-auth-browser-smoke');
  for (const probeName of ['web-journal-browser-smoke', 'web-room-browser-smoke']) {
    const probe = probesByName.get(probeName);
    assert.equal(String(probe.user_id ?? ''), String(authProbe.user_id ?? ''), `${probeName} user_id must match web-auth-browser-smoke`);
    assert.equal(String(probe.organization_id ?? ''), String(authProbe.organization_id ?? ''), `${probeName} organization_id must match web-auth-browser-smoke`);
  }
  assertSingleProbeLoadRun('CLIENT-WEB-001', probeLoadRunIDs);
}

function validateTenantRLSEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('DATA-RLS-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'DATA-RLS-001');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'DATA-RLS-001 report must include load_run_id');
  const ownerOrgID = String(report.owner_org_id ?? '').trim();
  const blockedOrgID = String(report.blocked_org_id ?? '').trim();
  assert.match(ownerOrgID, tenantOrgIDPattern, 'DATA-RLS-001 report must include UUID owner_org_id');
  assert.match(blockedOrgID, tenantOrgIDPattern, 'DATA-RLS-001 report must include UUID blocked_org_id');
  assert.notEqual(ownerOrgID.toLowerCase(), blockedOrgID.toLowerCase(), 'DATA-RLS-001 owner_org_id and blocked_org_id must be different');
  const reportCreatedJournalID = String(report.created_journal_id ?? '').trim();
  const reportCreatedRoomID = String(report.created_room_id ?? '').trim();
  assert.match(reportCreatedJournalID, tenantResourceIDPattern, 'DATA-RLS-001 report must include structured created_journal_id');
  assert.match(reportCreatedRoomID, tenantResourceIDPattern, 'DATA-RLS-001 report must include structured created_room_id');
  const reportReleaseMarkers = [];
  if (String(report.release_candidate ?? '').trim() || String(report.service_version ?? '').trim()) {
    reportReleaseMarkers.push(
      `release_candidate=${String(report.release_candidate ?? '').trim()}`,
      `service_version=${String(report.service_version ?? '').trim()}`,
      `load_run_id=${reportLoadRunID}`,
    );
  }
  const apiTarget = String(report.api_target ?? '');
  assert.match(apiTarget, /^https:\/\//, 'DATA-RLS-001 report must use HTTPS api_target');
  assertNonLocalOrPrivateTarget(apiTarget, `DATA-RLS-001 api_target must not be local/self-test: ${apiTarget}`);

  const requiredProbes = new Set([
    'owner-create-encrypted-journal',
    'blocked-journal-tenant-override-write-denied',
    'owner-read-created-journal',
    'owner-list-contains-created-journal',
    'blocked-read-created-journal',
    'blocked-list-excludes-created-journal',
    'owner-create-room',
    'blocked-room-tenant-override-write-denied',
    'owner-active-rooms-contains-created-room',
    'blocked-active-rooms-excludes-created-room',
    'owner-room-state',
    'blocked-room-state-denied',
    'database-rls-context-proof',
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const probeLoadRunIDs = new Set();
  assert.equal(probes.length, requiredProbes.size, 'DATA-RLS-001 report must include exactly the required tenant isolation probes');
  let createdJournalID = '';
  let createdRoomID = '';
  const expectedStatuses = new Map([
    ['owner-create-encrypted-journal', [201]],
    ['blocked-journal-tenant-override-write-denied', [400, 403]],
    ['owner-read-created-journal', [200]],
    ['owner-list-contains-created-journal', [200]],
    ['blocked-read-created-journal', [404]],
    ['blocked-list-excludes-created-journal', [200]],
    ['owner-create-room', [201]],
    ['blocked-room-tenant-override-write-denied', [400, 403]],
    ['owner-active-rooms-contains-created-room', [200]],
    ['blocked-active-rooms-excludes-created-room', [200]],
    ['owner-room-state', [200]],
    ['blocked-room-state-denied', [403]],
    ['database-rls-context-proof', [200]],
  ]);
  for (const probe of probes) {
    assert.ok(requiredProbes.delete(probe.name), `DATA-RLS-001 report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    const allowedStatuses = expectedStatuses.get(probe.name) ?? [];
    assert.ok(allowedStatuses.includes(probe.status_code), `${probe.name} must return HTTP ${allowedStatuses.join(' or ')}`);
    const target = String(probe.target ?? '');
    if (probe.name === 'database-rls-context-proof') {
      assert.match(target, /^https:\/\//, 'DATA-RLS-001 database-rls-context-proof target must be an HTTPS artifact URL');
      assertNonLocalOrPrivateTarget(target, `DATA-RLS-001 database RLS artifact must not be local/self-test: ${target}`);
      assertDistinctReportHosts('DATA-RLS-001', [
        ['api_target', apiTarget],
        ['database-rls-context-proof', target],
      ]);
      const summary = String(probe.result_summary ?? '');
      assert.equal(String(probe.application_role ?? ''), 'scriptureforge_app', 'DATA-RLS-001 database-rls-context-proof must include structured application_role=scriptureforge_app');
      assert.equal(String(probe.row_security ?? ''), 'on', 'DATA-RLS-001 database-rls-context-proof must include structured row_security=on');
      assert.equal(Number(probe.rls_tables_verified), 9, 'DATA-RLS-001 database-rls-context-proof must include structured rls_tables_verified=9');
      assert.equal(Number(probe.rls_forced_tables), 9, 'DATA-RLS-001 database-rls-context-proof must include structured rls_forced_tables=9');
      assert.equal(String(probe.rls_policy_scope ?? ''), 'app.current_org_id', 'DATA-RLS-001 database-rls-context-proof must include structured rls_policy_scope=app.current_org_id');
      assertTenantRLSTableOutcomes(probe);
      for (const marker of [
        ...requiredTenantRLSContextMarkers,
        `rls_table_names=${requiredAppGrantTableNames.join(',')}`,
        ...requiredTenantRLSTableOutcomeMarkers(),
        `app.current_org_id=${ownerOrgID}`,
        `blocked_org_id=${blockedOrgID}`,
        ...reportReleaseMarkers,
      ]) {
        assert.ok(
          summary.toLowerCase().includes(marker.toLowerCase()),
          `DATA-RLS-001 database-rls-context-proof result_summary must include verified marker ${marker}`,
        );
      }
      assert.deepEqual(probe.rls_table_names, requiredAppGrantTableNames, 'DATA-RLS-001 database-rls-context-proof structured rls_table_names must match every tenant-scoped table');
      assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    } else if (probe.name.includes('journal')) {
      assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS deployed API URL`);
      assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
      assert.ok(target.startsWith(`${apiTarget}/api/v1/journal_entries`), `${probe.name} target must use the canonical journal endpoint`);
      const summary = String(probe.result_summary ?? '');
      assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
      assertSummaryIncludesMarkers(probe.name, summary, [...(requiredTenantAPIProbeSummaryMarkers.get(probe.name) ?? []), ...reportReleaseMarkers]);
      if (probe.name !== 'blocked-journal-tenant-override-write-denied') {
        const journalID = String(probe.journal_id ?? '').trim();
        assert.match(journalID, tenantResourceIDPattern, `${probe.name} probe must include structured journal_id`);
        assertSummaryIncludesMarkers(probe.name, summary, [`journal_id=${journalID}`]);
        if (probe.name === 'owner-create-encrypted-journal') {
          createdJournalID = journalID;
        } else {
          assert.equal(journalID, createdJournalID, `${probe.name} journal_id must match owner-create-encrypted-journal journal_id`);
        }
      }
    } else {
      assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS deployed API URL`);
      assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
      assert.ok(target.startsWith(`${apiTarget}/api/v1/rooms/`), `${probe.name} target must use the canonical rooms endpoint`);
      const summary = String(probe.result_summary ?? '');
      assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
      assertSummaryIncludesMarkers(probe.name, summary, [...(requiredTenantAPIProbeSummaryMarkers.get(probe.name) ?? []), ...reportReleaseMarkers]);
      if (probe.name !== 'blocked-room-tenant-override-write-denied') {
        const roomID = String(probe.room_id ?? '').trim();
        assert.match(roomID, tenantResourceIDPattern, `${probe.name} probe must include structured room_id`);
        assertSummaryIncludesMarkers(probe.name, summary, [`room_id=${roomID}`]);
        if (probe.name === 'owner-create-room') {
          createdRoomID = roomID;
        } else {
          assert.equal(roomID, createdRoomID, `${probe.name} room_id must match owner-create-room room_id`);
        }
      }
    }
  }
  assert.equal(requiredProbes.size, 0, `DATA-RLS-001 report missing probes: ${[...requiredProbes].join(', ')}`);
  assert.equal(reportCreatedJournalID, createdJournalID, 'DATA-RLS-001 report created_journal_id must match owner-create-encrypted-journal journal_id');
  assert.equal(reportCreatedRoomID, createdRoomID, 'DATA-RLS-001 report created_room_id must match owner-create-room room_id');
  assertSingleProbeLoadRun('DATA-RLS-001', probeLoadRunIDs);
}

function requiredTenantRLSTableOutcomeMarkers() {
  return requiredAppGrantTableNames.flatMap((table) => [
    `rls_table_${table}_same_visible=true`,
    `rls_table_${table}_cross_hidden=true`,
    `rls_table_${table}_write_denied=true`,
  ]);
}

function assertTenantRLSTableOutcomes(probe) {
  const outcomes = Array.isArray(probe.rls_table_outcomes) ? probe.rls_table_outcomes : [];
  assert.equal(outcomes.length, requiredAppGrantTableNames.length, 'DATA-RLS-001 database-rls-context-proof must include structured rls_table_outcomes for every tenant-scoped table');
  for (const table of requiredAppGrantTableNames) {
    const outcome = outcomes.find((candidate) => String(candidate?.table ?? '') === table);
    assert.ok(outcome, `DATA-RLS-001 database-rls-context-proof missing rls_table_outcomes entry for ${table}`);
    assert.equal(outcome.same_visible, true, `DATA-RLS-001 database-rls-context-proof ${table} must include same_visible=true`);
    assert.equal(outcome.cross_hidden, true, `DATA-RLS-001 database-rls-context-proof ${table} must include cross_hidden=true`);
    assert.equal(outcome.write_denied, true, `DATA-RLS-001 database-rls-context-proof ${table} must include write_denied=true`);
  }
}

function validateMobileEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('CLIENT-MOBILE-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'CLIENT-MOBILE-001');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'CLIENT-MOBILE-001 report must include load_run_id');
  const reportMobileBuildID = String(report.mobile_build_id ?? '').trim();
  assert.match(reportMobileBuildID, mobileBuildIDPattern, 'CLIENT-MOBILE-001 report must include structured mobile_build_id');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
    `load_run_id=${reportLoadRunID}`,
  ];
  const requiredProbes = new Set([
    'mobile-eas-or-device-run',
    'mobile-native-crypto-smoke',
    'mobile-staging-config',
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  const probeLoadRunIDs = new Set();
  const mobileBuildIDs = new Set();
  assert.equal(probes.length, requiredProbes.size, 'CLIENT-MOBILE-001 report must include exactly the required mobile probes');
  for (const probe of probes) {
    assert.ok(requiredProbes.delete(probe.name), `CLIENT-MOBILE-001 report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 200, `${probe.name} must return HTTP 200`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS artifact URL`);
    assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
    const summary = String(probe.result_summary ?? '');
    assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    assertSummaryIncludesMarkers(probe.name, summary, [...(requiredMobileProbeSummaryMarkers.get(probe.name) ?? []), ...reportReleaseMarkers]);
    assertSummaryExcludesMarkers(probe.name, summary, forbiddenMobileProbeSummaryMarkers);
    if (probe.name === 'mobile-eas-or-device-run') {
      const mobileBuildID = String(probe.mobile_build_id ?? extractFirstMatch(summary, mobileBuildIDSummaryPattern)).trim();
      const platforms = String(probe.platforms ?? '').trim();
      const releaseChannel = String(probe.release_channel ?? '').trim();
      const expoProfile = String(probe.expo_profile ?? '').trim();
      assert.match(mobileBuildID, mobileBuildIDPattern, 'mobile-eas-or-device-run probe must include structured mobile_build_id');
      mobileBuildIDs.add(mobileBuildID);
      assert.match(platforms, mobilePlatformsPattern, 'mobile-eas-or-device-run probe must include structured platforms with android and ios');
      assert.match(releaseChannel, mobileReleaseChannelPattern, 'mobile-eas-or-device-run probe must include structured release_channel=staging');
      assert.match(expoProfile, mobileExpoProfilePattern, 'mobile-eas-or-device-run probe must include structured expo_profile=staging');
      assertSummaryIncludesMarkers(probe.name, summary, [
        `mobile_build_id=${mobileBuildID}`,
        `platforms=${platforms}`,
        `release_channel=${releaseChannel}`,
        `expo_profile=${expoProfile}`,
      ]);
    }
    if (probe.name === 'mobile-native-crypto-smoke') {
      const mobileBuildID = String(probe.mobile_build_id ?? extractFirstMatch(summary, mobileBuildIDSummaryPattern)).trim();
      const summaryProvider = extractFirstMatch(summary, mobileNativeProviderSummaryPattern);
      const summaryNativeRequired = extractFirstMatch(summary, mobileNativeRequiredSummaryPattern);
      const provider = String(probe.provider ?? summaryProvider).trim();
      const nativeRequired = String(probe.native_required ?? summaryNativeRequired).trim();
      const uniqueIV = String(probe.unique_iv ?? '').trim();
      const associatedDataSaltID = String(probe.associated_data_salt_id ?? extractFirstMatch(summary, mobileAssociatedDataSaltIDSummaryPattern)).trim();
      const associatedDataVersion = String(probe.associated_data_salt_version ?? extractFirstMatch(summary, mobileAssociatedDataVersionSummaryPattern)).trim();
      assert.match(mobileBuildID, mobileBuildIDPattern, 'mobile-native-crypto-smoke probe must include structured mobile_build_id');
      mobileBuildIDs.add(mobileBuildID);
      assert.match(summaryProvider, mobileNativeProviderPattern, 'mobile-native-crypto-smoke probe must include structured provider=react-native-quick-crypto');
      assert.match(summaryNativeRequired, mobileNativeRequiredPattern, 'mobile-native-crypto-smoke probe must include structured native_required=true');
      assert.match(provider, mobileNativeProviderPattern, 'mobile-native-crypto-smoke probe must include structured provider=react-native-quick-crypto');
      assert.match(nativeRequired, mobileNativeRequiredPattern, 'mobile-native-crypto-smoke probe must include structured native_required=true');
      assert.match(uniqueIV, mobileUniqueIVPattern, 'mobile-native-crypto-smoke probe must include structured unique_iv=true');
      assert.match(associatedDataSaltID, mobileAssociatedDataSaltIDPattern, 'mobile-native-crypto-smoke probe must include structured associated_data_salt_id');
      assert.match(associatedDataVersion, mobileAssociatedDataVersionPattern, 'mobile-native-crypto-smoke probe must include positive structured associated_data_salt_version');
      assertSummaryIncludesMarkers(probe.name, summary, [
        `mobile_build_id=${mobileBuildID}`,
        `provider=${provider}`,
        `native_required=${nativeRequired}`,
        `unique_iv=${uniqueIV}`,
        `associated_data_salt_id=${associatedDataSaltID}`,
        `associated_data_salt_version=${associatedDataVersion}`,
      ]);
    }
    if (probe.name === 'mobile-staging-config') {
      const mobileBuildID = String(probe.mobile_build_id ?? extractFirstMatch(summary, mobileBuildIDSummaryPattern)).trim();
      const apiBaseURL = String(probe.api_base_url ?? '').trim();
      const wsBaseURL = String(probe.ws_base_url ?? '').trim();
      const requireNativeCrypto = String(probe.require_native_crypto ?? '').trim();
      const deploymentEnvironment = String(probe.deployment_environment ?? '').trim();
      assert.match(mobileBuildID, mobileBuildIDPattern, 'mobile-staging-config probe must include structured mobile_build_id');
      mobileBuildIDs.add(mobileBuildID);
      assert.match(apiBaseURL, mobileAPIBaseURLPattern, 'mobile-staging-config probe must include structured HTTPS api_base_url');
      assert.match(wsBaseURL, mobileWSBaseURLPattern, 'mobile-staging-config probe must include structured WSS ws_base_url');
      assertNonLocalOrPrivateTarget(apiBaseURL, `mobile-staging-config api_base_url must not be local/self-test: ${apiBaseURL}`);
      assertNonLocalOrPrivateTarget(wsBaseURL, `mobile-staging-config ws_base_url must not be local/self-test: ${wsBaseURL}`);
      assert.match(requireNativeCrypto, mobileRequireNativeCryptoPattern, 'mobile-staging-config probe must include structured require_native_crypto=true');
      assert.match(deploymentEnvironment, mobileDeploymentEnvironmentPattern, 'mobile-staging-config probe must include structured deployment_environment=staging');
      assertSummaryIncludesMarkers(probe.name, summary, [
        `mobile_build_id=${mobileBuildID}`,
        `EXPO_PUBLIC_API_BASE_URL=${apiBaseURL}`,
        `EXPO_PUBLIC_WS_BASE_URL=${wsBaseURL}`,
        `EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=${requireNativeCrypto}`,
        `EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=${deploymentEnvironment}`,
      ]);
    }
  }
  assertDistinctReportURLs('CLIENT-MOBILE-001', probes.map((probe) => [probe.name, String(probe.target ?? '')]));
  assert.equal(mobileBuildIDs.size, 1, 'CLIENT-MOBILE-001 mobile_build_id values must match across mobile probes');
  assert.equal(reportMobileBuildID, [...mobileBuildIDs][0], 'CLIENT-MOBILE-001 report mobile_build_id must match mobile probe mobile_build_id');
  assert.equal(requiredProbes.size, 0, `CLIENT-MOBILE-001 report missing probes: ${[...requiredProbes].join(', ')}`);
  assertSummaryIncludesMarkers('CLIENT-MOBILE-001', probes.map((probe) => String(probe.result_summary ?? '')).join(' '), [
    'distinct_mobile_artifacts=true',
  ]);
  assertSingleProbeLoadRun('CLIENT-MOBILE-001', probeLoadRunIDs);
}

function validateRustEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('RUST-GRPC-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'RUST-GRPC-001');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
    `deployment_environment=${String(report.deployment_environment ?? '').trim()}`,
  ];
  assert.ok(String(report.deployment_environment ?? '').trim(), 'RUST-GRPC-001 report must include deployment_environment');
  const probeLoadRunIDs = new Set();
  const grpcTarget = String(report.grpc_target ?? '');
  assert.ok(grpcTarget.length > 0, 'RUST-GRPC-001 report must include grpc_target');
  assertNonLocalOrPrivateTarget(grpcTarget, `RUST-GRPC-001 grpc_target must not be local/self-test: ${grpcTarget}`);

  const metricsTarget = String(report.metrics_target ?? '');
  assert.match(metricsTarget, /^https?:\/\//, 'RUST-GRPC-001 report must include metrics_target');
  assertNonLocalOrPrivateTarget(metricsTarget, `RUST-GRPC-001 metrics_target must not be local/self-test: ${metricsTarget}`);

  const apiMetricsTarget = String(report.api_metrics_target ?? '');
  assert.match(apiMetricsTarget, /^https:\/\//, 'RUST-GRPC-001 report must include HTTPS api_metrics_target');
  assertNonLocalOrPrivateTarget(apiMetricsTarget, `RUST-GRPC-001 api_metrics_target must not be local/self-test: ${apiMetricsTarget}`);
  assert.notEqual(
    metricsTarget,
    apiMetricsTarget,
    'RUST-GRPC-001 metrics_target and api_metrics_target must be distinct',
  );
  assertDistinctReportURLs('RUST-GRPC-001', [
    ['metrics_target', metricsTarget],
    ['api_metrics_target', apiMetricsTarget],
  ]);

  const probes = Array.isArray(report.probes) ? report.probes : [];
  const probesByName = new Map(probes.map((probe) => [probe.name, probe]));
  const health = probesByName.get('rust-grpc-health');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'RUST-GRPC-001 report must include load_run_id');
  assert.ok(health, 'RUST-GRPC-001 report must include rust-grpc-health probe');
  assert.equal(health.passed, true, 'rust-grpc-health must pass');
  assert.equal(health.status, 'SERVING', 'rust-grpc-health must report SERVING');
  assert.equal(String(health.target ?? ''), grpcTarget, 'rust-grpc-health target must match grpc_target');
  assertSummaryIncludesMarkers('rust-grpc-health', String(health.result_summary ?? ''), [
    ...(requiredRustProbeSummaryMarkers.get('rust-grpc-health') ?? []),
    ...reportReleaseMarkers,
    assertProbeLoadRunBinding('rust-grpc-health', String(health.result_summary ?? ''), reportLoadRunID, probeLoadRunIDs),
  ]);

  const metrics = probesByName.get('rust-metrics');
  assert.ok(metrics, 'RUST-GRPC-001 report must include rust-metrics probe');
  assert.equal(metrics.passed, true, 'rust-metrics must pass');
  assert.equal(metrics.status_code, 200, 'rust-metrics must return HTTP 200');
  assert.equal(String(metrics.target ?? ''), metricsTarget, 'rust-metrics target must match metrics_target');
  assertSummaryIncludesMarkers('rust-metrics', String(metrics.result_summary ?? ''), [
    ...(requiredRustProbeSummaryMarkers.get('rust-metrics') ?? []),
    ...reportReleaseMarkers,
    assertProbeLoadRunBinding('rust-metrics', String(metrics.result_summary ?? ''), reportLoadRunID, probeLoadRunIDs),
  ]);
  assert.ok(Number(metrics.embedding_requests) > 0, 'rust-metrics must include positive structured embedding_requests');
  assert.ok(Number(metrics.vector_search_requests) > 0, 'rust-metrics must include positive structured vector_search_requests');
  assertSummaryIncludesMarkers('rust-metrics', String(metrics.result_summary ?? ''), [
    `embedding_requests=${Number(metrics.embedding_requests)}`,
    `vector_search_requests=${Number(metrics.vector_search_requests)}`,
  ]);

  const apiMetrics = probesByName.get('api-rust-integration-metrics');
  assert.ok(apiMetrics, 'RUST-GRPC-001 report must include api-rust-integration-metrics probe');
  assert.equal(apiMetrics.passed, true, 'api-rust-integration-metrics must pass');
  assert.equal(apiMetrics.status_code, 200, 'api-rust-integration-metrics must return HTTP 200');
  assert.equal(String(apiMetrics.target ?? ''), apiMetricsTarget, 'api-rust-integration-metrics target must match api_metrics_target');
  assertSummaryIncludesMarkers('api-rust-integration-metrics', String(apiMetrics.result_summary ?? ''), [
    ...(requiredRustProbeSummaryMarkers.get('api-rust-integration-metrics') ?? []),
    ...reportReleaseMarkers,
    assertProbeLoadRunBinding('api-rust-integration-metrics', String(apiMetrics.result_summary ?? ''), reportLoadRunID, probeLoadRunIDs),
  ]);
  assert.ok(Number(apiMetrics.api_rust_vector_search_ops) > 0, 'api-rust-integration-metrics must include positive structured api_rust_vector_search_ops');
  assert.ok(Number(apiMetrics.api_rust_vector_search_seconds) > 0, 'api-rust-integration-metrics must include positive structured api_rust_vector_search_seconds');
  assertSummaryIncludesMarkers('api-rust-integration-metrics', String(apiMetrics.result_summary ?? ''), [
    `api_rust_vector_search_ops=${Number(apiMetrics.api_rust_vector_search_ops)}`,
    `api_rust_vector_search_seconds=${Number(apiMetrics.api_rust_vector_search_seconds)}`,
  ]);
  assert.equal(probeLoadRunIDs.size, 1, 'RUST-GRPC-001 probe result_summary load_run_id values must all match');
}

function validateZoomEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('EXT-ZOOM-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'EXT-ZOOM-001');
  assert.ok(String(report.release_candidate ?? '').trim(), 'EXT-ZOOM-001 report must include release_candidate');
  assert.ok(String(report.service_version ?? '').trim(), 'EXT-ZOOM-001 report must include service_version');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
  ];
  const requiredProbes = new Set([
    'zoom-oauth-readiness',
    'zoom-meeting-create-or-fallback',
    'zoom-timeout-circuit-fallback',
    'zoom-webhook-signature-delivery',
    'zoom-webhook-url-validation',
    'zoom-duplicate-webhook-idempotency',
    'zoom-meeting-room-mapping',
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, requiredProbes.size, 'EXT-ZOOM-001 report must include exactly the required Zoom probes');
  const zoomArtifactTargets = [];
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  if (String(manifest.release_candidate ?? '').trim()) {
    assert.ok(reportLoadRunID, 'EXT-ZOOM-001 report must include load_run_id');
  }
  const probeLoadRunIDs = new Set();
  for (const probe of probes) {
    assert.ok(requiredProbes.delete(probe.name), `EXT-ZOOM-001 report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 200, `${probe.name} must return HTTP 200`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS artifact URL`);
    assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
    zoomArtifactTargets.push([`${probe.name} target`, target]);
    const summary = String(probe.result_summary ?? '');
    const probeLoadRunMarker = assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    if (probe.name === 'zoom-meeting-create-or-fallback') {
      assert.ok(
        zoomMeetingCreateOrFallbackSummaryMarkerSets.some((markers) => summaryIncludesAll(summary, [...markers, ...reportReleaseMarkers, probeLoadRunMarker])),
        'zoom-meeting-create-or-fallback result_summary must include meeting or offline fallback markers',
      );
    } else {
      assertSummaryIncludesMarkers(probe.name, summary, [
        ...(requiredZoomProbeSummaryMarkers.get(probe.name) ?? []),
        ...reportReleaseMarkers,
        probeLoadRunMarker,
      ]);
    }
    assertSummaryExcludesMarkers(probe.name, summary, forbiddenZoomProbeSummaryMarkers);
    if (probe.name === 'zoom-webhook-signature-delivery') {
      const webhookSignature = String(probe.webhook_signature ?? '').trim();
      const webhookTimestamp = String(probe.webhook_timestamp ?? '').trim();
      assert.match(webhookSignature, zoomWebhookSignaturePattern, 'zoom-webhook-signature-delivery probe must include structured webhook_signature');
      assert.match(webhookTimestamp, zoomWebhookTimestampPattern, 'zoom-webhook-signature-delivery probe must include structured webhook_timestamp');
      assert.equal(probe.stale_rejected, true, 'zoom-webhook-signature-delivery probe must include structured stale_rejected=true');
      assert.equal(probe.replay_rejected, true, 'zoom-webhook-signature-delivery probe must include structured replay_rejected=true');
      assert.equal(probe.invalid_signature_rejected, true, 'zoom-webhook-signature-delivery probe must include structured invalid_signature_rejected=true');
      assert.equal(probe.signed_delivery_accepted, true, 'zoom-webhook-signature-delivery probe must include structured signed_delivery_accepted=true');
      assertSummaryIncludesMarkers(probe.name, summary, [
        `x-zm-signature=${webhookSignature}`,
        `x-zm-request-timestamp=${webhookTimestamp}`,
        'stale_rejected=true',
        'replay_rejected=true',
        'invalid_signature_rejected=true',
        'signed_delivery_accepted=true',
      ]);
    }
    if (probe.name === 'zoom-timeout-circuit-fallback') {
      assert.equal(probe.provider_timeout, true, 'zoom-timeout-circuit-fallback probe must include structured provider_timeout=true');
      assert.equal(probe.circuit_open, true, 'zoom-timeout-circuit-fallback probe must include structured circuit_open=true');
      assert.equal(probe.offline_fallback, true, 'zoom-timeout-circuit-fallback probe must include structured offline_fallback=true');
      assertSummaryIncludesMarkers(probe.name, summary, [
        'provider_timeout=true',
        'circuit_open=true',
        'offline_fallback=true',
      ]);
    }
    if (probe.name === 'zoom-webhook-url-validation') {
      const plainToken = String(probe.plain_token ?? '').trim();
      const encryptedToken = String(probe.encrypted_token ?? '').trim();
      const validationResponse = String(probe.validation_response ?? '').trim();
      assert.match(plainToken, zoomValidationTokenPattern, 'zoom-webhook-url-validation probe must include structured plain_token');
      assert.match(encryptedToken, zoomValidationTokenPattern, 'zoom-webhook-url-validation probe must include structured encrypted_token');
      assert.match(validationResponse, zoomValidationResponsePattern, 'zoom-webhook-url-validation probe must include structured validation_response=200');
      assertSummaryIncludesMarkers(probe.name, summary, [
        `plain_token=${plainToken}`,
        `encrypted_token=${encryptedToken}`,
        `validation_response=${validationResponse}`,
      ]);
    }
    if (probe.name === 'zoom-duplicate-webhook-idempotency') {
      const deliveryID = String(probe.delivery_id ?? '').trim();
      const trackingID = String(probe.tracking_id ?? '').trim();
      assert.match(deliveryID, zoomDeliveryIDPattern, 'zoom-duplicate-webhook-idempotency probe must include structured delivery_id');
      assert.match(trackingID, zoomTrackingIDPattern, 'zoom-duplicate-webhook-idempotency probe must include structured tracking_id');
      assert.equal(probe.single_state_mutation, true, 'zoom-duplicate-webhook-idempotency probe must include structured single_state_mutation=true');
      assert.equal(probe.no_duplicate_side_effects, true, 'zoom-duplicate-webhook-idempotency probe must include structured no_duplicate_side_effects=true');
      assertSummaryIncludesMarkers(probe.name, summary, [
        `delivery_id=${deliveryID}`,
        `x-zm-trackingid=${trackingID}`,
        'single_state_mutation=true',
        'no_duplicate_side_effects=true',
      ]);
    }
    if (probe.name === 'zoom-meeting-room-mapping') {
      const meetingID = String(probe.meeting_external_id ?? '').trim();
      const roomID = String(probe.internal_room_id ?? '').trim();
      assert.match(meetingID, zoomMappingIDPattern, 'zoom-meeting-room-mapping probe must include structured meeting_external_id');
      assert.match(roomID, zoomMappingIDPattern, 'zoom-meeting-room-mapping probe must include structured internal_room_id');
      assertSummaryIncludesMarkers(probe.name, summary, [`meeting_external_id=${meetingID}`, `internal_room_id=${roomID}`]);
    }
  }
  assertDistinctReportURLs('EXT-ZOOM-001', zoomArtifactTargets);
  assertSingleProbeLoadRun('EXT-ZOOM-001', probeLoadRunIDs);
  assert.equal(requiredProbes.size, 0, `EXT-ZOOM-001 report missing probes: ${[...requiredProbes].join(', ')}`);
}

function validateAIEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('EXT-AI-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'EXT-AI-001');
  const requiredProbes = new Set([
    'ai-provider-config',
    'ai-generation-route',
    'ai-timeout-degradation',
    'ai-citation-verification',
    'ai-audit-persistence',
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, requiredProbes.size, 'EXT-AI-001 report must include exactly the required AI probes');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
  ];
  const aiArtifactTargets = [];
  let generationRequestID = '';
  let generationOrganizationID = '';
  let generationUserID = '';
  let auditRequestID = '';
  let auditOrganizationID = '';
  let auditUserID = '';
  let citationVerificationID = '';
  let auditCitationID = '';
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  if (String(manifest.release_candidate ?? '').trim()) {
    assert.ok(reportLoadRunID, 'EXT-AI-001 report must include load_run_id');
  }
  const probeLoadRunIDs = new Set();
  for (const probe of probes) {
    assert.ok(requiredProbes.delete(probe.name), `EXT-AI-001 report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 200, `${probe.name} must return HTTP 200`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS artifact URL`);
    assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
    aiArtifactTargets.push([`${probe.name} target`, target]);
    const summary = String(probe.result_summary ?? '');
    const probeLoadRunMarker = assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    assertSummaryIncludesMarkers(probe.name, summary, [
      ...(requiredAIProbeSummaryMarkers.get(probe.name) ?? []),
      ...reportReleaseMarkers,
      probeLoadRunMarker,
    ]);
    assertSummaryExcludesMarkers(probe.name, summary, forbiddenAIProbeSummaryMarkers);
    if (probe.name === 'ai-provider-config') {
      const provider = String(probe.ai_provider ?? '').trim();
      const model = String(probe.ai_chat_model ?? '').trim();
      const endpoint = String(probe.ai_chat_endpoint ?? '').trim();
      const timeoutMS = String(probe.ai_http_timeout_ms ?? '').trim();
      const maxRetries = String(probe.ai_max_retries ?? '').trim();
      assert.match(provider, aiProviderPattern, 'ai-provider-config probe must include structured ai_provider');
      assert.match(model, aiModelPattern, 'ai-provider-config probe must include structured ai_chat_model');
      assert.match(endpoint, aiEndpointPattern, 'ai-provider-config probe must include structured https ai_chat_endpoint');
      assert.match(timeoutMS, aiPositiveIntegerPattern, 'ai-provider-config probe must include structured positive ai_http_timeout_ms');
      assert.match(maxRetries, aiNonNegativeIntegerPattern, 'ai-provider-config probe must include structured ai_max_retries');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        `AI_PROVIDER=${provider}`,
        `AI_CHAT_MODEL=${model}`,
        `AI_CHAT_ENDPOINT=${endpoint}`,
        `AI_HTTP_TIMEOUT_MS=${timeoutMS}`,
        `AI_MAX_RETRIES=${maxRetries}`,
      ]);
    }
    if (probe.name === 'ai-timeout-degradation') {
      assert.equal(probe.provider_timeout, true, 'ai-timeout-degradation probe must include structured provider_timeout=true');
      assert.equal(probe.retry_exhausted, true, 'ai-timeout-degradation probe must include structured retry_exhausted=true');
      assert.equal(probe.fail_closed, true, 'ai-timeout-degradation probe must include structured fail_closed=true');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        'provider_timeout=true',
        'retry_exhausted=true',
        'fail_closed=true',
      ]);
    }
    if (probe.name === 'ai-generation-route') {
      generationRequestID = String(probe.request_id ?? '').trim();
      generationOrganizationID = String(probe.organization_id ?? '').trim();
      generationUserID = String(probe.user_id ?? '').trim();
      assert.match(generationRequestID, aiRequestIDPattern, 'ai-generation-route probe must include structured request_id');
      assert.match(generationOrganizationID, aiPrincipalIDPattern, 'ai-generation-route probe must include structured organization_id');
      assert.match(generationUserID, aiPrincipalIDPattern, 'ai-generation-route probe must include structured user_id');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        `organization_id=${generationOrganizationID}`,
        `user_id=${generationUserID}`,
        `request_id=${generationRequestID}`,
      ]);
    }
    if (probe.name === 'ai-citation-verification') {
      citationVerificationID = String(probe.citation_id ?? '').trim();
      assert.match(citationVerificationID, aiCitationIDPattern, 'ai-citation-verification probe must include structured citation_id');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [`citation_id=${citationVerificationID}`]);
    }
    if (probe.name === 'ai-audit-persistence') {
      auditRequestID = String(probe.request_id ?? '').trim();
      auditOrganizationID = String(probe.organization_id ?? '').trim();
      auditUserID = String(probe.user_id ?? '').trim();
      auditCitationID = String(probe.citation_id ?? '').trim();
      assert.match(auditRequestID, aiRequestIDPattern, 'ai-audit-persistence probe must include structured request_id');
      assert.match(auditOrganizationID, aiPrincipalIDPattern, 'ai-audit-persistence probe must include structured organization_id');
      assert.match(auditUserID, aiPrincipalIDPattern, 'ai-audit-persistence probe must include structured user_id');
      assert.match(auditCitationID, aiCitationIDPattern, 'ai-audit-persistence probe must include structured citation_id');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        `organization_id=${auditOrganizationID}`,
        `user_id=${auditUserID}`,
        `request_id=${auditRequestID}`,
        `citation_id=${auditCitationID}`,
      ]);
    }
  }
  assert.equal(
    auditOrganizationID,
    generationOrganizationID,
    'EXT-AI-001 ai-audit-persistence organization_id must match ai-generation-route organization_id',
  );
  assert.equal(
    auditUserID,
    generationUserID,
    'EXT-AI-001 ai-audit-persistence user_id must match ai-generation-route user_id',
  );
  assert.equal(
    auditRequestID,
    generationRequestID,
    'EXT-AI-001 ai-audit-persistence request_id must match ai-generation-route request_id',
  );
  assert.equal(
    auditCitationID,
    citationVerificationID,
    'EXT-AI-001 ai-audit-persistence citation_id must match ai-citation-verification citation_id',
  );
  assertDistinctReportURLs('EXT-AI-001', aiArtifactTargets);
  assertSingleProbeLoadRun('EXT-AI-001', probeLoadRunIDs);
  assert.equal(requiredProbes.size, 0, `EXT-AI-001 report missing probes: ${[...requiredProbes].join(', ')}`);
}

function validateObservabilityEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  const requiredProbes = new Set();
  if (evidenceItems.includes('OBS-OTEL-001')) {
    assertReportReleaseMatchesManifest(report, manifest, 'OBS-OTEL-001');
    for (const name of [
      'collector-otlp-config',
      'api-prometheus-metrics',
      'rust-prometheus-metrics',
      'trace-backend-search',
      'log-backend-trace-correlation',
    ]) {
      requiredProbes.add(name);
    }
  }
  if (evidenceItems.includes('OBS-ALERT-001')) {
    assertReportReleaseMatchesManifest(report, manifest, 'OBS-ALERT-001');
    for (const name of [
      'dashboard-import',
      'alert-rules-loaded',
      'alert-delivery-status',
      'telemetry-retention-policy',
    ]) {
      requiredProbes.add(name);
    }
  }
  if (requiredProbes.size === 0) {
    return;
  }
  assert.ok(String(report.release_candidate ?? '').trim(), 'observability report must include release_candidate');
  assert.ok(String(report.service_version ?? '').trim(), 'observability report must include service_version');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'observability report must include load_run_id');
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, requiredProbes.size, 'observability report must include exactly the required probes for requested evidence items');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
    `load_run_id=${reportLoadRunID}`,
  ];
  const observedProbes = new Map();
  const otelArtifactTargets = [];
  const alertArtifactTargets = [];
  const otelProbeNames = new Set(['collector-otlp-config', 'api-prometheus-metrics', 'rust-prometheus-metrics', 'trace-backend-search', 'log-backend-trace-correlation']);
  const alertProbeNames = new Set(['dashboard-import', 'alert-rules-loaded', 'alert-delivery-status', 'telemetry-retention-policy']);
  const probeLoadRunIDs = new Set();
  for (const probe of probes) {
    assert.ok(requiredProbes.delete(probe.name), `observability report includes unexpected or duplicate probe ${probe.name}`);
    observedProbes.set(probe.name, probe);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 200, `${probe.name} must return HTTP 200`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https?:\/\//, `${probe.name} target must be an HTTP(S) staging URL`);
    assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
    if (otelProbeNames.has(probe.name)) {
      otelArtifactTargets.push([`${probe.name} target`, target]);
    }
    if (alertProbeNames.has(probe.name)) {
      alertArtifactTargets.push([`${probe.name} target`, target]);
    }
    const summary = String(probe.result_summary ?? '');
    const probeLoadRunMarker = assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    assertSummaryIncludesMarkers(probe.name, summary, [
      ...(requiredObservabilityProbeSummaryMarkers.get(probe.name) ?? []),
      ...reportReleaseMarkers,
      probeLoadRunMarker,
    ]);
    assertSummaryExcludesMarkers(probe.name, summary, forbiddenObservabilityProbeSummaryMarkers);
  }
  assert.equal(requiredProbes.size, 0, `observability report missing probes: ${[...requiredProbes].join(', ')}`);
  assertSingleProbeLoadRun('observability report', probeLoadRunIDs);
  if (evidenceItems.includes('OBS-OTEL-001')) {
    assertDistinctReportURLs('OBS-OTEL-001', otelArtifactTargets);
    const traceID = String(report.trace_id ?? '').trim();
    assert.ok(traceID, 'OBS-OTEL-001 report must include trace_id');
    assertValidTraceID(traceID, 'OBS-OTEL-001 trace_id');
    const observedRoute = String(report.observed_route ?? '').trim();
    const httpMethod = String(report.http_method ?? '').trim().toUpperCase();
    const tenantID = String(report.tenant_id ?? '').trim();
    const userID = String(report.user_id ?? '').trim();
    const role = String(report.role ?? '').trim();
    assert.ok(observedRoute.startsWith('/'), 'OBS-OTEL-001 report must include observed_route as an absolute route path');
    assert.match(httpMethod, /^[A-Z]+$/, 'OBS-OTEL-001 report must include http_method as an uppercase method token');
    assert.match(tenantID, /^\S+$/, 'OBS-OTEL-001 report must include tenant_id as a concrete token');
    assert.match(userID, /^\S+$/, 'OBS-OTEL-001 report must include user_id as a concrete token');
    assert.match(role, /^\S+$/, 'OBS-OTEL-001 report must include role as a concrete token');
    for (const probeName of ['trace-backend-search', 'log-backend-trace-correlation']) {
      const probe = observedProbes.get(probeName);
      const probeTraceID = String(probe?.trace_id ?? '').trim();
      const probeObservedRoute = String(probe?.observed_route ?? '').trim();
      const probeHTTPMethod = String(probe?.http_method ?? '').trim().toUpperCase();
      assertValidTraceID(probeTraceID, `${probeName} structured trace_id`);
      assert.equal(probeTraceID, traceID, `${probeName} structured trace_id must match report trace_id`);
      assert.equal(probeObservedRoute, observedRoute, `${probeName} structured observed_route must match report observed_route`);
      assert.match(probeHTTPMethod, observabilityMethodPattern, `${probeName} structured http_method must be an uppercase method token`);
      assert.equal(probeHTTPMethod, httpMethod, `${probeName} structured http_method must match report http_method`);
      assert.ok(targetIncludesTraceID(probe?.target, traceID), `${probeName} target must include report trace_id`);
      assertSummaryIncludesMarkers(probeName, String(probe?.result_summary ?? ''), [
        traceID,
        `route=${observedRoute}`,
        `method=${httpMethod}`,
      ]);
    }
    const logProbe = observedProbes.get('log-backend-trace-correlation');
    const logTenantID = String(logProbe?.tenant_id ?? '').trim();
    const logUserID = String(logProbe?.user_id ?? '').trim();
    const logRole = String(logProbe?.role ?? '').trim();
    assert.match(logTenantID, observabilityPrincipalPattern, 'log-backend-trace-correlation structured tenant_id must be a concrete token');
    assert.match(logUserID, observabilityPrincipalPattern, 'log-backend-trace-correlation structured user_id must be a concrete token');
    assert.match(logRole, observabilityPrincipalPattern, 'log-backend-trace-correlation structured role must be a concrete token');
    assert.equal(logTenantID, tenantID, 'log-backend-trace-correlation structured tenant_id must match report tenant_id');
    assert.equal(logUserID, userID, 'log-backend-trace-correlation structured user_id must match report user_id');
    assert.equal(logRole, role, 'log-backend-trace-correlation structured role must match report role');
    assertSummaryIncludesMarkers('log-backend-trace-correlation', String(logProbe?.result_summary ?? ''), [
      `tenant_id=${tenantID}`,
      `user_id=${userID}`,
      `role=${role}`,
    ]);
  }
  if (evidenceItems.includes('OBS-ALERT-001')) {
    assertDistinctReportURLs('OBS-ALERT-001', alertArtifactTargets);
    const alertName = String(report.alert_name ?? '').trim();
    const alertReceiver = String(report.alert_receiver ?? '').trim();
    assert.match(alertName, /^\S+$/, 'OBS-ALERT-001 report must include alert_name as a concrete token');
    assert.match(alertReceiver, /^\S+$/, 'OBS-ALERT-001 report must include alert_receiver as a concrete token');
    const deliveryProbe = observedProbes.get('alert-delivery-status');
    const deliveryAlertName = String(deliveryProbe?.alert_name ?? '').trim();
    const deliveryAlertReceiver = String(deliveryProbe?.alert_receiver ?? '').trim();
    const deliveryID = String(deliveryProbe?.delivery_id ?? '').trim();
    assert.match(deliveryAlertName, observabilityPrincipalPattern, 'OBS-ALERT-001 alert-delivery-status probe must include structured alert_name');
    assert.match(deliveryAlertReceiver, observabilityPrincipalPattern, 'OBS-ALERT-001 alert-delivery-status probe must include structured alert_receiver');
    assert.equal(deliveryAlertName, alertName, 'OBS-ALERT-001 alert-delivery-status structured alert_name must match report alert_name');
    assert.equal(deliveryAlertReceiver, alertReceiver, 'OBS-ALERT-001 alert-delivery-status structured alert_receiver must match report alert_receiver');
    assert.match(deliveryID, observabilityDeliveryIDPattern, 'OBS-ALERT-001 alert-delivery-status probe must include structured delivery_id');
    assertSummaryIncludesMarkers('alert-delivery-status', String(deliveryProbe?.result_summary ?? ''), [
      `alertname=${alertName}`,
      `receiver=${alertReceiver}`,
      `delivery_id=${deliveryID}`,
    ]);
  }
}

function assertValidTraceID(traceID, label) {
  assert.match(traceID, /^[0-9a-f]{32}$/, `${label} must be a 32-character lowercase hex OpenTelemetry trace ID`);
  assert.notEqual(traceID, '00000000000000000000000000000000', `${label} must not be all zeroes`);
}

function concreteIAMRoleARN(summary) {
  const match = String(summary ?? '').match(concreteIAMRoleARNPattern);
  return match?.[0]?.replace(/^role_arn=/i, '') ?? '';
}

function validateSecurityEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  const requiredArtifactProbes = new Set();
  if (evidenceItems.includes('SEC-SECRETS-001')) {
    assertReportReleaseMatchesManifest(report, manifest, 'SEC-SECRETS-001');
    for (const name of [
      'irsa-service-account',
      'secret-provider-class',
      'synced-secret-metadata-redacted',
      'iam-secrets-policy',
      'scoped-secrets-access-test',
    ]) {
      requiredArtifactProbes.add(name);
    }
  }
  const requiresDBUser = evidenceItems.includes('SEC-DBUSER-001');
  if (requiresDBUser) {
    assertReportReleaseMatchesManifest(report, manifest, 'SEC-DBUSER-001');
  }
  if (requiredArtifactProbes.size === 0 && !requiresDBUser) {
    return;
  }
  assert.ok(String(report.release_candidate ?? '').trim(), 'security report must include release_candidate');
  assert.ok(String(report.service_version ?? '').trim(), 'security report must include service_version');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
  ];
  const expectedProbeCount = requiredArtifactProbes.size + (requiresDBUser ? 1 : 0);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, expectedProbeCount, 'security report must include exactly the required probes for requested evidence items');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'security report must include load_run_id');

  let sawDBUser = false;
  const secretArtifactTargets = [];
  const securityRoleARNs = new Map();
  const probeLoadRunIDs = new Set();
  for (const probe of probes) {
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    if (requiredArtifactProbes.has(probe.name)) {
      requiredArtifactProbes.delete(probe.name);
      assert.equal(probe.status_code, 200, `${probe.name} must return HTTP 200`);
      const target = String(probe.target ?? '');
      assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS artifact URL`);
      assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
      secretArtifactTargets.push([`${probe.name} target`, target]);
      const summary = String(probe.result_summary ?? '');
      for (const marker of [...(requiredSecurityProbeSummaryMarkers.get(probe.name) ?? []), ...reportReleaseMarkers]) {
        assert.ok(
          summary.toLowerCase().includes(marker.toLowerCase()),
          `${probe.name} result_summary must include verified marker ${marker}`,
        );
      }
      assertSummaryIncludesMarkers(probe.name, summary, [
        assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs),
      ]);
      if (securityRoleARNProbeNames.has(probe.name)) {
        const summaryRoleARN = concreteIAMRoleARN(summary);
        const structuredRoleARN = String(probe.role_arn ?? '').trim();
        assert.match(
          summary,
          concreteIAMRoleARNPattern,
          `${probe.name} result_summary must include concrete IAM role ARN marker`,
        );
        if (structuredRoleARN) {
          assert.match(
            structuredRoleARN,
            /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]+$/,
            `${probe.name} must include structured concrete role_arn`,
          );
          assert.equal(
            structuredRoleARN,
            summaryRoleARN,
            `${probe.name} structured role_arn must match result_summary role_arn marker`,
          );
        }
        securityRoleARNs.set(probe.name, summaryRoleARN);
      }
      continue;
    }
    if (probe.name === 'database-scoped-user' && requiresDBUser && !sawDBUser) {
      sawDBUser = true;
      assert.equal(String(probe.target ?? ''), 'redacted-database-url', 'database-scoped-user target must stay redacted');
      const summary = String(probe.result_summary ?? '');
      assert.match(summary, /connected as/i, 'database-scoped-user summary must prove a live connection');
      assert.match(summary, /connected as "?scriptureforge_app"?/i, 'database-scoped-user summary must prove connected as scriptureforge_app');
      assert.equal(String(probe.current_user ?? ''), 'scriptureforge_app', 'database-scoped-user structured current_user must be scriptureforge_app');
      assert.equal(probe.superuser, false, 'database-scoped-user structured superuser must be false');
      assert.equal(probe.bypassrls, false, 'database-scoped-user structured bypassrls must be false');
      assert.equal(probe.createrole, false, 'database-scoped-user structured createrole must be false');
      assert.equal(probe.createdb, false, 'database-scoped-user structured createdb must be false');
      assert.equal(probe.privileged_operation_denied, true, 'database-scoped-user structured privileged_operation_denied must be true');
      assert.equal(probe.app_grants_verified, true, 'database-scoped-user structured app_grants_verified must be true');
      assert.equal(probe.app_grant_tables, 9, 'database-scoped-user structured app_grant_tables must be 9');
      assert.deepEqual(probe.app_grant_table_names, requiredAppGrantTableNames, 'database-scoped-user structured app_grant_table_names must match required tenant tables');
      assert.deepEqual(probe.app_grants, ['SELECT', 'INSERT', 'UPDATE', 'DELETE'], 'database-scoped-user structured app_grants must be SELECT,INSERT,UPDATE,DELETE');
      assert.match(summary, /current_user=scriptureforge_app/i, 'database-scoped-user summary must prove current_user=scriptureforge_app');
      assert.match(summary, /superuser=false/i, 'database-scoped-user summary must prove superuser=false');
      assert.match(summary, /bypassrls=false/i, 'database-scoped-user summary must prove bypassrls=false');
      assert.match(summary, /createrole=false/i, 'database-scoped-user summary must prove createrole=false');
      assert.match(summary, /createdb=false/i, 'database-scoped-user summary must prove createdb=false');
      assert.match(summary, /privileged_operation_denied=true/i, 'database-scoped-user summary must prove privileged_operation_denied=true');
      assert.match(summary, /app_grants_verified=true/i, 'database-scoped-user summary must prove app_grants_verified=true');
      assert.match(summary, /app_grant_tables=9/i, 'database-scoped-user summary must prove app_grant_tables=9');
      assert.match(summary, /app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails/i, 'database-scoped-user summary must prove required app grant table names');
      assert.match(summary, /app_grants=SELECT,INSERT,UPDATE,DELETE/i, 'database-scoped-user summary must prove SELECT,INSERT,UPDATE,DELETE app grants');
      assert.ok(
        summary.toLowerCase().includes('staging artifact'),
        'database-scoped-user result_summary must include verified marker staging artifact',
      );
      for (const marker of reportReleaseMarkers) {
        assert.ok(
          summary.toLowerCase().includes(marker.toLowerCase()),
          `database-scoped-user result_summary must include verified marker ${marker}`,
        );
      }
      assertSummaryIncludesMarkers('database-scoped-user', summary, [
        assertProbeLoadRunBinding('database-scoped-user', summary, reportLoadRunID, probeLoadRunIDs),
      ]);
      continue;
    }
    assert.fail(`security report includes unexpected or duplicate probe ${probe.name}`);
  }
  if (evidenceItems.includes('SEC-SECRETS-001')) {
    assertDistinctReportURLs('SEC-SECRETS-001', secretArtifactTargets);
    assertEqualSecurityRoleARNs(securityRoleARNs);
  }
  assert.equal(requiredArtifactProbes.size, 0, `security report missing probes: ${[...requiredArtifactProbes].join(', ')}`);
  if (requiresDBUser) {
    assert.equal(sawDBUser, true, 'SEC-DBUSER-001 report missing database-scoped-user probe');
  }
  assertSingleProbeLoadRun('security report', probeLoadRunIDs);
}

function assertEqualSecurityRoleARNs(roleARNs) {
  for (const probeName of securityRoleARNProbeNames) {
    assert.ok(roleARNs.has(probeName), `SEC-SECRETS-001 report missing role_arn for ${probeName}`);
  }
  const uniqueRoleARNs = new Set(roleARNs.values());
  assert.equal(
    uniqueRoleARNs.size,
    1,
    'SEC-SECRETS-001 secret evidence role_arn values must match across IRSA, SecretProviderClass, IAM policy, and access-test probes',
  );
}

function validateResilienceEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  const requiredProbes = new Set();
  if (evidenceItems.includes('DR-ROLLBACK-001')) {
    assertReportReleaseMatchesManifest(report, manifest, 'DR-ROLLBACK-001');
    for (const name of [
      'api-ready-before-rollback',
      'rollback-rollout-artifact',
      'api-ready-after-rollback',
      'degradation-drill-artifact',
    ]) {
      requiredProbes.add(name);
    }
  }
  if (evidenceItems.includes('DR-BACKUP-001')) {
    assertReportReleaseMatchesManifest(report, manifest, 'DR-BACKUP-001');
    for (const name of [
      'backup-snapshot-artifact',
      'restore-drill-artifact',
      'restored-database-smoke',
    ]) {
      requiredProbes.add(name);
    }
  }
  if (requiredProbes.size === 0) {
    return;
  }
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, requiredProbes.size, 'resilience report must include exactly the required probes for requested evidence items');
  const rollbackArtifactTargets = [];
  const backupArtifactTargets = [];
  let preRollbackVersion = '';
  let postRollbackVersion = '';
  let rolledBackFrom = '';
  let rolledBackTo = '';
  let backupSnapshotID = '';
  let restoreSourceSnapshotID = '';
  const rollbackProbeNames = new Set([
    'api-ready-before-rollback',
    'rollback-rollout-artifact',
    'api-ready-after-rollback',
    'degradation-drill-artifact',
  ]);
  const backupProbeNames = new Set([
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ]);
  const reportReleaseMarkers = [];
  if (String(report.release_candidate ?? '').trim() || String(report.service_version ?? '').trim()) {
    reportReleaseMarkers.push(
      `release_candidate=${String(report.release_candidate ?? '').trim()}`,
      `service_version=${String(report.service_version ?? '').trim()}`,
    );
  }
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  const probeLoadRunIDs = new Set();
  for (const probe of probes) {
    assert.ok(requiredProbes.delete(probe.name), `resilience report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 200, `${probe.name} must return HTTP 200`);
    const target = String(probe.target ?? '');
    assert.match(target, /^https:\/\//, `${probe.name} target must be an HTTPS staging URL or artifact URL`);
    assertNonLocalOrPrivateTarget(target, `${probe.name} target must not be local/self-test: ${target}`);
    if (rollbackProbeNames.has(probe.name)) {
      rollbackArtifactTargets.push([probe.name, target]);
    }
    if (backupProbeNames.has(probe.name)) {
      backupArtifactTargets.push([probe.name, target]);
    }
    const probeSummary = String(probe.result_summary ?? '');
    const probeLoadRunID = summaryMarkerValue(probeSummary, 'load_run_id');
    assert.ok(probeLoadRunID, `${probe.name} result_summary must include verified marker load_run_id=`);
    if (reportLoadRunID) {
      assert.equal(
        probeLoadRunID,
        reportLoadRunID,
        `${probe.name} result_summary load_run_id must match report load_run_id`,
      );
    }
    probeLoadRunIDs.add(probeLoadRunID);
    assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
      ...(requiredResilienceProbeSummaryMarkers.get(probe.name) ?? []),
      ...reportReleaseMarkers,
      `load_run_id=${probeLoadRunID}`,
    ]);
    assertSummaryExcludesMarkers(probe.name, String(probe.result_summary ?? ''), forbiddenResilienceSummaryMarkers);
    if (probe.name === 'backup-snapshot-artifact') {
      const snapshotID = String(probe.snapshot_id ?? '').trim();
      const kmsKeyID = String(probe.kms_key_id ?? '').trim();
      backupSnapshotID = snapshotID;
      assert.match(snapshotID, resilienceIdentifierPattern, 'backup-snapshot-artifact probe must include structured snapshot_id');
      assert.match(kmsKeyID, resilienceKMSKeyIDPattern, 'backup-snapshot-artifact probe must include structured kms_key_id');
      assert.equal(Number.isInteger(probe.rpo_minutes) && probe.rpo_minutes > 0, true, 'backup-snapshot-artifact probe must include positive structured rpo_minutes');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        `snapshot_id=${snapshotID}`,
        `kms_key_id=${kmsKeyID}`,
        `rpo_minutes=${probe.rpo_minutes}`,
      ]);
    }
    if (probe.name === 'api-ready-before-rollback') {
      preRollbackVersion = String(probe.pre_rollback_version ?? '').trim();
      assert.match(preRollbackVersion, resilienceIdentifierPattern, 'api-ready-before-rollback probe must include structured pre_rollback_version');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        `pre_rollback_version=${preRollbackVersion}`,
      ]);
    }
    if (probe.name === 'api-ready-after-rollback') {
      postRollbackVersion = String(probe.post_rollback_version ?? '').trim();
      rolledBackFrom = String(probe.rolled_back_from ?? '').trim();
      rolledBackTo = String(probe.rolled_back_to ?? '').trim();
      assert.match(postRollbackVersion, resilienceIdentifierPattern, 'api-ready-after-rollback probe must include structured post_rollback_version');
      assert.match(rolledBackFrom, resilienceIdentifierPattern, 'api-ready-after-rollback probe must include structured rolled_back_from');
      assert.match(rolledBackTo, resilienceIdentifierPattern, 'api-ready-after-rollback probe must include structured rolled_back_to');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        `post_rollback_version=${postRollbackVersion}`,
        `rolled_back_from=${rolledBackFrom}`,
        `rolled_back_to=${rolledBackTo}`,
      ]);
    }
    if (probe.name === 'restore-drill-artifact') {
      const restoreJobID = String(probe.restore_job_id ?? '').trim();
      const sourceSnapshotID = String(probe.source_snapshot_id ?? '').trim();
      restoreSourceSnapshotID = sourceSnapshotID;
      assert.match(restoreJobID, resilienceIdentifierPattern, 'restore-drill-artifact probe must include structured restore_job_id');
      assert.match(sourceSnapshotID, resilienceIdentifierPattern, 'restore-drill-artifact probe must include structured source_snapshot_id');
      assert.equal(Number.isInteger(probe.rto_minutes) && probe.rto_minutes > 0, true, 'restore-drill-artifact probe must include positive structured rto_minutes');
      assert.equal(Number.isInteger(probe.restore_duration_minutes) && probe.restore_duration_minutes > 0, true, 'restore-drill-artifact probe must include positive structured restore_duration_minutes');
      assert.equal(
        probe.restore_duration_minutes <= probe.rto_minutes,
        true,
        'restore-drill-artifact restore_duration_minutes must be less than or equal to rto_minutes',
      );
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        `restore_job_id=${restoreJobID}`,
        `source snapshot_id=${sourceSnapshotID}`,
        `rto_minutes=${probe.rto_minutes}`,
        `restore_duration_minutes=${probe.restore_duration_minutes}`,
      ]);
    }
    if (probe.name === 'degradation-drill-artifact') {
      assert.equal(probe.ai_fault, true, 'degradation-drill-artifact probe must include structured ai_fault=true');
      assert.equal(probe.zoom_offline_fallback, true, 'degradation-drill-artifact probe must include structured zoom_offline_fallback=true');
      assert.equal(probe.non_ai_routes_healthy, true, 'degradation-drill-artifact probe must include structured non_ai_routes_healthy=true');
      assert.equal(probe.zoom_circuit_open, true, 'degradation-drill-artifact probe must include structured zoom_circuit_open=true');
      assertSummaryIncludesMarkers(probe.name, String(probe.result_summary ?? ''), [
        'ai_fault=true',
        'zoom_offline_fallback=true',
        'non_ai_routes_healthy=true',
        'zoom_circuit_open=true',
      ]);
    }
  }
  if (evidenceItems.includes('DR-ROLLBACK-001')) {
    assert.equal(
      rolledBackFrom,
      preRollbackVersion,
      'DR-ROLLBACK-001 api-ready-after-rollback rolled_back_from must match api-ready-before-rollback pre_rollback_version',
    );
    assert.equal(
      rolledBackTo,
      postRollbackVersion,
      'DR-ROLLBACK-001 api-ready-after-rollback rolled_back_to must match api-ready-after-rollback post_rollback_version',
    );
    assert.notEqual(
      postRollbackVersion,
      preRollbackVersion,
      'DR-ROLLBACK-001 post_rollback_version must differ from pre_rollback_version',
    );
    assertDistinctReportURLs('DR-ROLLBACK-001', rollbackArtifactTargets);
  }
  if (evidenceItems.includes('DR-BACKUP-001')) {
    assert.equal(
      restoreSourceSnapshotID,
      backupSnapshotID,
      'DR-BACKUP-001 restore-drill-artifact source_snapshot_id must match backup-snapshot-artifact snapshot_id',
    );
    assertDistinctReportURLs('DR-BACKUP-001', backupArtifactTargets);
  }
  assert.equal(
    probeLoadRunIDs.size,
    1,
    'resilience report probe result_summary load_run_id values must all match',
  );
  assert.ok(reportLoadRunID, 'resilience report must include load_run_id');
  assert.equal(requiredProbes.size, 0, `resilience report missing probes: ${[...requiredProbes].join(', ')}`);
}

function validateAbuseEvidence(report, manifest) {
  const evidenceItems = report.evidence_items ?? [];
  if (!evidenceItems.includes('ABUSE-LIMIT-001')) {
    return;
  }
  assertReportReleaseMatchesManifest(report, manifest, 'ABUSE-LIMIT-001');
  assert.ok(String(report.release_candidate ?? '').trim(), 'ABUSE-LIMIT-001 report must include release_candidate');
  assert.ok(String(report.service_version ?? '').trim(), 'ABUSE-LIMIT-001 report must include service_version');
  const reportLoadRunID = String(report.load_run_id ?? '').trim();
  assert.ok(reportLoadRunID, 'ABUSE-LIMIT-001 report must include load_run_id');
  const reportReleaseMarkers = [
    `release_candidate=${String(report.release_candidate ?? '').trim()}`,
    `service_version=${String(report.service_version ?? '').trim()}`,
    `load_run_id=${reportLoadRunID}`,
  ];
  const apiTarget = String(report.api_target ?? '');
  assert.match(apiTarget, /^https:\/\//, 'ABUSE-LIMIT-001 report must use HTTPS api_target');
  assertNonLocalOrPrivateTarget(apiTarget, `ABUSE-LIMIT-001 api_target must not be local/self-test: ${apiTarget}`);
  const webOrigin = String(report.web_origin ?? '');
  assert.match(webOrigin, /^https:\/\//, 'ABUSE-LIMIT-001 report must include HTTPS web_origin');
  assertNonLocalOrPrivateTarget(webOrigin, `ABUSE-LIMIT-001 web_origin must not be local/self-test: ${webOrigin}`);
  const configArtifactURL = String(report.config_artifact_url ?? '');
  assert.match(configArtifactURL, /^https:\/\//, 'ABUSE-LIMIT-001 report must include HTTPS config_artifact_url');
  assertNonLocalOrPrivateTarget(configArtifactURL, `ABUSE-LIMIT-001 config_artifact_url must not be local/self-test: ${configArtifactURL}`);
  assertDistinctReportHosts('ABUSE-LIMIT-001', [
    ['api_target', apiTarget],
    ['web_origin', webOrigin],
    ['config_artifact_url', configArtifactURL],
  ]);
  assert.equal(report.config_artifact_verified, true, 'ABUSE-LIMIT-001 report must prove config_artifact_verified=true');
  const probeLoadRunIDs = new Set();
  const configSummary = String(report.config_artifact_summary ?? '');
  assertProbeLoadRunBinding('ABUSE-LIMIT-001 config_artifact_summary', configSummary, reportLoadRunID, probeLoadRunIDs);
  assertSummaryIncludesMarkers('ABUSE-LIMIT-001 config_artifact_summary', configSummary, [...requiredAbuseConfigSummaryMarkers, ...reportReleaseMarkers]);
  assertAbuseConfigAssignments(configSummary);

  const requiredProfiles = new Set([
    'auth-rate-limit',
    'auth-account-rate-limit',
    'auth-refresh-rate-limit',
    'ai-rate-limit',
    'journal-rate-limit',
    'rooms-rate-limit',
    'websocket-rate-limit',
  ]);
  const probes = Array.isArray(report.probes) ? report.probes : [];
  assert.equal(probes.length, requiredProfiles.size, 'ABUSE-LIMIT-001 report must include exactly the required abuse profiles');
  for (const probe of probes) {
    assert.ok(requiredProfiles.delete(probe.name), `ABUSE-LIMIT-001 report includes unexpected or duplicate probe ${probe.name}`);
    assert.equal(probe.passed, true, `${probe.name} must pass`);
    assert.equal(probe.status_code, 429, `${probe.name} must observe HTTP 429`);
    assert.ok(Number.isInteger(probe.attempts) && probe.attempts >= 2, `${probe.name} must prove repeated attempts before HTTP 429`);
    assertPositiveIntegerHeader(probe.retry_after, `${probe.name} Retry-After`);
    assertPositiveIntegerHeader(probe.rate_limit, `${probe.name} X-RateLimit-Limit`);
    assertExactIntegerHeader(probe.rate_limit_remaining, 0, `${probe.name} X-RateLimit-Remaining`);
    assertPositiveIntegerHeader(probe.rate_limit_reset, `${probe.name} X-RateLimit-Reset`);
    if (probe.name === 'auth-account-rate-limit') {
      assert.equal(probe.account_scoped, true, 'auth-account-rate-limit must prove account_scoped=true');
      assert.equal(probe.forwarded_client_ip_rotated, true, 'auth-account-rate-limit must prove forwarded_client_ip_rotated=true');
    }
    if (probe.name === 'auth-refresh-rate-limit') {
      assert.equal(probe.refresh_token_scoped, true, 'auth-refresh-rate-limit must prove refresh_token_scoped=true');
    }
    if (probe.name === 'websocket-rate-limit') {
      assert.equal(probe.websocket_upgrade, true, 'websocket-rate-limit must prove websocket_upgrade=true');
    }
    const summary = String(probe.result_summary ?? '');
    assertProbeLoadRunBinding(probe.name, summary, reportLoadRunID, probeLoadRunIDs);
    assertSummaryIncludesMarkers(probe.name, summary, [...(requiredAbuseProbeSummaryMarkers.get(probe.name) ?? []), ...reportReleaseMarkers]);
  }
  assert.equal(requiredProfiles.size, 0, `ABUSE-LIMIT-001 report missing profiles: ${[...requiredProfiles].join(', ')}`);
  assertSingleProbeLoadRun('ABUSE-LIMIT-001', probeLoadRunIDs);
}

function assertAbuseConfigAssignments(summary) {
  for (const key of abuseConfigAssignmentKeys) {
    const match = new RegExp(`\\b${key}=([0-9]+)\\b`).exec(summary);
    assert.ok(match, `ABUSE-LIMIT-001 config_artifact_summary must include concrete ${key}=<positive integer>`);
    const value = Number.parseInt(match[1], 10);
    assert.ok(value > 0, `ABUSE-LIMIT-001 config_artifact_summary ${key} must be a positive integer`);
  }
}

function assertPositiveIntegerHeader(value, label) {
  const parsed = Number.parseInt(String(value ?? '').trim(), 10);
  assert.ok(Number.isInteger(parsed) && String(parsed) === String(value ?? '').trim() && parsed > 0, `${label} must be a positive integer`);
}

function assertExactIntegerHeader(value, expected, label) {
  const parsed = Number.parseInt(String(value ?? '').trim(), 10);
  assert.ok(Number.isInteger(parsed) && String(parsed) === String(value ?? '').trim() && parsed === expected, `${label} must equal ${expected}`);
}

async function readJSON(path) {
  const content = await readFile(path, 'utf8');
  return JSON.parse(content.replace(/^\uFEFF/, ''));
}

function recordEvidence(manifest, report, artifact, command) {
  assert.equal(report.threshold_pass, true, 'probe report threshold_pass must be true before recording passed evidence');
  assert.ok(Array.isArray(report.evidence_items), 'probe report must include evidence_items');
  assert.ok(report.evidence_items.length > 0, 'probe report must include at least one evidence item');
  assert.match(report.observed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'probe report observed_at must be ISO UTC without milliseconds');
  validateCIEvidence(report, manifest);
  validateTLSEvidence(report, manifest);
  validateTerraformEvidence(report, manifest);
  validateKubernetesEvidence(report, manifest);
  validateWebClientEvidence(report, manifest);
  validateTenantRLSEvidence(report, manifest);
  validateMobileEvidence(report, manifest);
  validateRustEvidence(report, manifest);
  validateZoomEvidence(report, manifest);
  validateAIEvidence(report, manifest);
  validateObservabilityEvidence(report, manifest);
  validateSecurityEvidence(report, manifest);
  validateResilienceEvidence(report, manifest);
  validatePerformanceEvidence(report, manifest);
  validateAbuseEvidence(report, manifest);
  assertReportLoadRunMatchesManifest(manifest, report);

  const itemsById = new Map(manifest.items.map((item) => [item.id, item]));
  for (const id of report.evidence_items) {
    const item = itemsById.get(id);
    assert.ok(item, `manifest missing evidence item ${id}`);
    item.status = 'passed';
    item.evidence ??= [];
    const alreadyRecorded = item.evidence.some((entry) => entry.artifact === artifact && entry.command_or_probe === command);
    if (!alreadyRecorded) {
      item.evidence.push({
        observed_at: report.observed_at,
        command_or_probe: command,
        artifact,
        result_summary: summarizeProbeReport(report),
      });
    }
  }
  manifest.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  return manifest;
}

function recordManualEvidence(manifest, itemID, artifact, command, summary, observedAt, options = {}) {
  assert.ok(!probeBackedEvidenceItems.has(itemID), `${itemID} must be recorded from its dedicated probe report, not manual --item-id mode`);
  assert.match(observedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'observedAt must be ISO UTC without milliseconds');
  assert.ok(summary.trim().length > 0, 'summary must not be empty');
  const item = manifest.items.find((candidate) => candidate.id === itemID);
  assert.ok(item, `manifest missing evidence item ${itemID}`);
  if (itemID === 'SEC-SIGNOFF-001') {
    const releaseCandidate = String(manifest.release_candidate ?? '').trim();
    assert.ok(releaseCandidate, `${itemID} manual evidence requires manifest release_candidate`);
    assert.ok(isDurableSignoffArtifact(artifact), `${itemID} artifact must be a security signoff document path or HTTPS approval URL`);
    if (isRepoLocalSignoffArtifact(artifact)) {
      const artifactText = String(options.artifactText ?? '');
      assert.ok(artifactText.trim().length > 0, `${itemID} local signoff artifact must be read and non-empty`);
      assertSummaryIncludesMarkers(itemID, artifactText, [
        ...requiredSecuritySignoffSummaryMarkers,
        `release_candidate=${releaseCandidate}`,
      ]);
    }
    assertSummaryIncludesMarkers(itemID, summary, [
      ...requiredSecuritySignoffSummaryMarkers,
      `release_candidate=${releaseCandidate}`,
    ]);
  }
  item.status = 'passed';
  item.evidence ??= [];
  const alreadyRecorded = item.evidence.some((entry) => entry.artifact === artifact && entry.command_or_probe === command);
  if (!alreadyRecorded) {
    item.evidence.push({
      observed_at: observedAt,
      command_or_probe: command,
      artifact,
      result_summary: summary,
    });
  }
  manifest.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  return manifest;
}

function isDurableSignoffArtifact(artifact) {
  const value = String(artifact ?? '').trim();
  if (/^https:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      return !isLocalOrPrivateTarget(url.href) && !isReservedPlaceholderTarget(value);
    } catch {
      return false;
    }
  }
  const normalized = value.replaceAll('\\', '/').toLowerCase();
  return normalized.startsWith('security/')
    && normalized.endsWith('.md')
    && /signoff|approval|release-risk|risk-signoff/.test(normalized);
}

function isRepoLocalSignoffArtifact(artifact) {
  const value = String(artifact ?? '').trim();
  return !/^https:\/\//i.test(value) && isDurableSignoffArtifact(value);
}

function recordStatus(manifest, itemID, status, details) {
  const item = manifest.items.find((candidate) => candidate.id === itemID);
  assert.ok(item, `manifest missing evidence item ${itemID}`);
  assert.ok(['blocked', 'failed', 'accepted_risk'].includes(status), `unsupported status ${status}`);
  item.status = status;
  delete item.evidence;
  if (status === 'blocked' || status === 'failed') {
    assert.ok(details.owner?.trim(), `${status} status requires owner`);
    assert.ok(details.blocker?.trim(), `${status} status requires blocker`);
    item.owner = details.owner;
    item.blocker = details.blocker;
    delete item.decision_ref;
    delete item.accepted_by;
    delete item.review_due_at;
    delete item.expires_at;
  }
  if (status === 'accepted_risk') {
    assert.ok(details.decisionRef?.trim(), 'accepted_risk status requires decisionRef');
    assert.ok(details.owner?.trim(), 'accepted_risk status requires owner');
    assert.ok(details.acceptedBy?.trim(), 'accepted_risk status requires acceptedBy');
    assert.match(details.reviewDueAt ?? '', /^\d{4}-\d{2}-\d{2}$/, 'accepted_risk status requires reviewDueAt as YYYY-MM-DD');
    assert.match(details.expiresAt ?? '', /^\d{4}-\d{2}-\d{2}$/, 'accepted_risk status requires expiresAt as YYYY-MM-DD');
    assert.ok(
      details.reviewDueAt <= details.expiresAt,
      'accepted_risk status requires reviewDueAt on or before expiresAt',
    );
    const recordDate = details.currentDate ?? new Date().toISOString().slice(0, 10);
    assert.match(recordDate, /^\d{4}-\d{2}-\d{2}$/, 'accepted_risk status requires currentDate as YYYY-MM-DD');
    assert.ok(
      details.expiresAt >= recordDate,
      'accepted_risk status requires expiresAt that is not already expired',
    );
    assert.ok(
      details.reviewDueAt >= recordDate,
      'accepted_risk status requires reviewDueAt that is not already overdue',
    );
    item.decision_ref = details.decisionRef;
    item.owner = details.owner;
    item.accepted_by = details.acceptedBy;
    item.review_due_at = details.reviewDueAt;
    item.expires_at = details.expiresAt;
    delete item.blocker;
  }
  manifest.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  return manifest;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = await readJSON(args.manifest);
  let updated;
  let recordedCount;
  if (args['probe-report']) {
    const report = await readJSON(args['probe-report']);
    updated = recordEvidence(manifest, report, args.artifact, args.command);
    recordedCount = report.evidence_items.length;
  } else {
    if (args.status) {
      updated = recordStatus(manifest, args['item-id'], args.status, {
        owner: args.owner,
        blocker: args.blocker,
        decisionRef: args['decision-ref'],
        acceptedBy: args['accepted-by'],
        reviewDueAt: args['review-due-at'],
        expiresAt: args['expires-at'],
      });
    } else {
      const observedAt = args['observed-at'] ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
      const artifactText = args['item-id'] === 'SEC-SIGNOFF-001' && isRepoLocalSignoffArtifact(args.artifact)
        ? await readFile(args.artifact, 'utf8')
        : undefined;
      updated = recordManualEvidence(manifest, args['item-id'], args.artifact, args.command, args.summary, observedAt, { artifactText });
    }
    recordedCount = 1;
  }
  await writeFile(args.manifest, `${JSON.stringify(updated, null, 2)}\n`);
  console.log(`recorded ${recordedCount} evidence item(s) into ${args.manifest}`);
}

if (import.meta.url === `file://${process.argv[1].replaceAll('\\', '/')}` || process.argv[1]?.endsWith('record-staging-evidence.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

export { parseArgs, recordEvidence, recordManualEvidence, recordStatus, summarizeProbeReport };
