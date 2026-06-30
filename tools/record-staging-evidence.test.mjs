import assert from 'node:assert/strict';
import test from 'node:test';

import { parseArgs, recordEvidence, recordManualEvidence, recordStatus, summarizeProbeReport } from './record-staging-evidence.mjs';
import { ciReleaseEvidenceProofMarkers } from './write-ci-release-evidence.mjs';

const tenantRLSMarkerSummary = [
  'staging artifact',
  'current_user=scriptureforge_app',
  'non-superuser',
  'superuser=false',
  'bypassrls=false',
  'app.current_org_id',
  'app.current_org_id=11111111-1111-4111-8111-111111111111',
  "current_setting('app.current_org_id')",
  'blocked_org_id=22222222-2222-4222-8222-222222222222',
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
  'distinct_db_rls_artifact=true',
].join(', ');

const tenantAPIProbeMarkerSummaries = {
  'owner-create-encrypted-journal': 'create returned HTTP 201; verified markers: same-tenant journal write accepted, encrypted journal created, plaintext not returned, plaintext-shaped journal payload denied, malformed encrypted envelope rejected, journal_id=entry-1',
  'blocked-journal-tenant-override-write-denied': 'tenant override journal write returned HTTP 400; verified markers: cross-tenant journal write denied, tenant override rejected',
  'owner-read-created-journal': 'read returned HTTP 200; verified markers: same-tenant journal read visible, created journal returned, journal_id=entry-1',
  'owner-list-contains-created-journal': 'owner list returned HTTP 200; verified markers: same-tenant journal list visible, created journal present, journal_id=entry-1',
  'blocked-read-created-journal': 'read returned HTTP 404; verified markers: cross-tenant journal read denied, created journal hidden, journal_id=entry-1',
  'blocked-list-excludes-created-journal': 'blocked list returned HTTP 200; verified markers: cross-tenant journal list hidden, created journal absent, journal_id=entry-1',
  'owner-create-room': 'room create returned HTTP 201; verified markers: same-tenant room write accepted, room created, room_id=room-1',
  'blocked-room-tenant-override-write-denied': 'tenant override room write returned HTTP 400; verified markers: cross-tenant room write denied, tenant override rejected',
  'owner-active-rooms-contains-created-room': 'active rooms returned HTTP 200; verified markers: same-tenant room list visible, created room present, room_id=room-1',
  'blocked-active-rooms-excludes-created-room': 'active rooms returned HTTP 200; verified markers: cross-tenant room list hidden, created room absent, room_id=room-1',
  'owner-room-state': 'room state probe returned HTTP 200; verified markers: same-tenant room state visible, created room state returned, room_id=room-1',
  'blocked-room-state-denied': 'room state probe returned HTTP 403; verified markers: cross-tenant room state denied, created room state hidden, room_id=room-1',
};

function tenantAPIProbe(name, overrides = {}) {
  const journalProbes = new Set([
    'owner-create-encrypted-journal',
    'owner-read-created-journal',
    'owner-list-contains-created-journal',
    'blocked-read-created-journal',
    'blocked-list-excludes-created-journal',
  ]);
  const roomProbes = new Set([
    'owner-create-room',
    'owner-active-rooms-contains-created-room',
    'blocked-active-rooms-excludes-created-room',
    'owner-room-state',
    'blocked-room-state-denied',
  ]);
  return {
    ...(journalProbes.has(name) ? { journal_id: 'entry-1' } : {}),
    ...(roomProbes.has(name) ? { room_id: 'room-1' } : {}),
    name,
    passed: true,
    result_summary: tenantAPIProbeMarkerSummaries[name],
    ...overrides,
  };
}

function tenantRLSProbeReport(overridesByProbe = {}) {
  const probe = (name, defaults = {}) => tenantAPIProbe(name, { ...defaults, ...(overridesByProbe[name] ?? {}) });
  return {
    observed_at: '2026-06-25T12:00:00Z',
    threshold_pass: true,
    api_target: 'https://api.staging.scriptureforge.ai',
    owner_org_id: '11111111-1111-4111-8111-111111111111',
    blocked_org_id: '22222222-2222-4222-8222-222222222222',
    evidence_items: ['DATA-RLS-001'],
    probes: [
      probe('owner-create-encrypted-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 201 }),
      {
        name: 'blocked-journal-tenant-override-write-denied',
        passed: true,
        target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries',
        status_code: 400,
        result_summary: tenantAPIProbeMarkerSummaries['blocked-journal-tenant-override-write-denied'],
        ...(overridesByProbe['blocked-journal-tenant-override-write-denied'] ?? {}),
      },
      probe('owner-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 200 }),
      probe('owner-list-contains-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
      probe('blocked-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 404 }),
      probe('blocked-list-excludes-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
      probe('owner-create-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 201 }),
      {
        name: 'blocked-room-tenant-override-write-denied',
        passed: true,
        target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create',
        status_code: 400,
        result_summary: tenantAPIProbeMarkerSummaries['blocked-room-tenant-override-write-denied'],
        ...(overridesByProbe['blocked-room-tenant-override-write-denied'] ?? {}),
      },
      probe('owner-active-rooms-contains-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
      probe('blocked-active-rooms-excludes-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
      probe('owner-room-state', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 200 }),
      probe('blocked-room-state-denied', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 403 }),
      {
        name: 'database-rls-context-proof',
        passed: true,
        target: 'https://artifacts.staging.scriptureforge.ai/data/rls-db-proof.txt',
        status_code: 200,
        application_role: 'scriptureforge_app',
        row_security: 'on',
        rls_tables_verified: 9,
        rls_forced_tables: 9,
        rls_policy_scope: 'app.current_org_id',
        result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary}`,
        ...(overridesByProbe['database-rls-context-proof'] ?? {}),
      },
    ],
  };
}

const webSmokeProbeMarkerSummaries = {
  'web-auth-browser-smoke': 'got HTTP 200 in 12ms; verified markers: staging artifact, login, register, authenticated, https://, user_id=user-staging, organization_id=org-staging, distinct_web_artifacts=true',
  'web-journal-browser-smoke': 'got HTTP 200 in 12ms; verified markers: staging artifact, journal, encrypted, save, load, plaintext absent associated data wrong associated data rejected, user_id=user-staging, organization_id=org-staging, journal_id=journal-staging, distinct_web_artifacts=true',
  'web-room-browser-smoke': 'got HTTP 200 in 12ms; verified markers: staging artifact, room, create, select, WebSocket, connected, user_id=user-staging, organization_id=org-staging, room_id=room-staging, distinct_web_artifacts=true',
};

function webSmokeProbes(releaseCandidate = '', serviceVersion = '', overridesByProbe = {}) {
  const releaseMarkers = releaseCandidate || serviceVersion
    ? `, release_candidate=${releaseCandidate}, service_version=${serviceVersion}`
    : '';
  return [
    {
      name: 'web-auth-browser-smoke',
      passed: true,
      target: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
      status_code: 200,
      user_id: 'user-staging',
      organization_id: 'org-staging',
      result_summary: webSmokeProbeMarkerSummaries['web-auth-browser-smoke'] + releaseMarkers,
      ...(overridesByProbe['web-auth-browser-smoke'] ?? {}),
    },
    {
      name: 'web-journal-browser-smoke',
      passed: true,
      target: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
      status_code: 200,
      user_id: 'user-staging',
      organization_id: 'org-staging',
      journal_id: 'journal-staging',
      result_summary: webSmokeProbeMarkerSummaries['web-journal-browser-smoke'] + releaseMarkers,
      ...(overridesByProbe['web-journal-browser-smoke'] ?? {}),
    },
    {
      name: 'web-room-browser-smoke',
      passed: true,
      target: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
      status_code: 200,
      user_id: 'user-staging',
      organization_id: 'org-staging',
      room_id: 'room-staging',
      result_summary: webSmokeProbeMarkerSummaries['web-room-browser-smoke'] + releaseMarkers,
      ...(overridesByProbe['web-room-browser-smoke'] ?? {}),
    },
  ];
}

const securityProbeMarkerSummaries = {
  'irsa-service-account': 'got HTTP 200; verified markers: staging artifact, namespace=staging, service_account=scriptureforge-api, role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets, eks.amazonaws.com/role-arn, scriptureforge, trust policy, sts:AssumeRoleWithWebIdentity, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'secret-provider-class': 'got HTTP 200; verified markers: staging artifact, namespace=staging, service_account=scriptureforge-api, role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets, SecretProviderClass, secrets-store.csi.k8s.io, provider, aws, objects, objectName, objectType, secretsmanager, objectAlias, jmesPath, secretObjects, type, Opaque, DATABASE_URL, JWT_SECRET_KEY, OPENAI_API_KEY, ZOOM_WEBHOOK_SECRET_TOKEN, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'synced-secret-metadata-redacted': 'got HTTP 200; verified markers: staging artifact, namespace=staging, scriptureforge-runtime-secrets, type, Opaque, DATABASE_URL, JWT_SECRET_KEY, OPENAI_API_KEY, ZOOM_WEBHOOK_SECRET_TOKEN, redacted, stringData absent, managed by secrets-store.csi.k8s.io, ownerReferences, secrets-store.csi.k8s.io/managed=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'iam-secrets-policy': 'got HTTP 200; verified markers: staging artifact, role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets, secretsmanager:GetSecretValue, secretsmanager:DescribeSecret, arn:aws:secretsmanager:, scoped resource, no wildcard resources, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'scoped-secrets-access-test': 'got HTTP 200; verified markers: staging artifact, namespace=staging, service_account=scriptureforge-api, role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets, allowed, configured secret, denied, unscoped secret, AccessDenied, distinct_secret_artifacts=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
};

const deploymentProbeMarkerSummaries = {
  'terraform-remote-backend-init': 'got HTTP 200; staging artifact; verified markers: terraform, s3, backend, bucket, key, encrypt=true, dynamodb_table, successfully initialized, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'terraform-staging-plan': 'got HTTP 200; staging artifact; verified markers: Terraform, Plan:, aws_eks_cluster, aws_eks_node_group, aws_rds_cluster, aws_elasticache_replication_group, aws_ecr_repository, kubernetes_deployment, kubernetes_ingress_v1, kubernetes_horizontal_pod_autoscaler_v2, kubernetes_pod_disruption_budget_v1, kubernetes_manifest, aws_iam_role, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'terraform-staging-apply-or-approval': 'got HTTP 200; staging artifact; verified markers: deployment approval, approved, DEPLOY-TF-001, change_ticket=PLATFORM-123, release_candidate=abc123, service_version=scriptureforge-api:abc123, distinct_terraform_artifacts=true',
  'kubernetes-rollout-status': 'got HTTP 200; staging artifact; verified markers: namespace, staging, deployment, scriptureforge-api, scriptureforge-web, scriptureforge-rust-engine, successfully rolled out, ready, available, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'kubernetes-workload-resources': 'got HTTP 200; staging artifact; verified markers: namespace, staging, deployment, service, ingress, hpa, pdb, ready, available, targets, minavailable, readinessProbe, livenessProbe, rollingUpdate, maxUnavailable=0, minReplicas, maxReplicas, tls, SecretProviderClass, image, scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc, release_candidate=abc123, service_version=scriptureforge-api:abc123, scriptureforge-api, scriptureforge-web, scriptureforge-rust-engine, distinct_kubernetes_artifacts=true',
};

function terraformApplyProbe(resultSummary = deploymentProbeMarkerSummaries['terraform-staging-apply-or-approval'], overrides = {}) {
  return {
    name: 'terraform-staging-apply-or-approval',
    passed: true,
    target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-apply.txt',
    status_code: 200,
    change_ticket: 'PLATFORM-123',
    result_summary: resultSummary,
    ...overrides,
  };
}

const stagingProbeMarkerSummaries = {
  'api-live': 'got HTTP 200; verified markers: api-live, /live, HTTP 200, release_candidate=abc123, service_version=scriptureforge-web:abc123',
  'api-ready': 'got HTTP 200; verified markers: api-ready, /ready, HTTP 200, release_candidate=abc123, service_version=scriptureforge-web:abc123',
  'api-tls': 'TLS1.3 certificate valid; verified markers: api-tls, TLS, certificate, cert_not_after, release_candidate=abc123, service_version=scriptureforge-web:abc123',
  'api-http-redirect': 'got HTTP 301 redirect; verified markers: api-http-redirect, HTTP, HTTPS, redirect, release_candidate=abc123, service_version=scriptureforge-web:abc123',
  'web-root': 'got HTTP 200; verified markers: web-root, web root, HTTP 200, release_candidate=abc123, service_version=scriptureforge-web:abc123',
  'web-tls': 'TLS1.3 certificate valid; verified markers: web-tls, TLS, certificate, cert_not_after, release_candidate=abc123, service_version=scriptureforge-web:abc123',
  'web-http-redirect': 'got HTTP 301 redirect; verified markers: web-http-redirect, HTTP, HTTPS, redirect, release_candidate=abc123, service_version=scriptureforge-web:abc123',
};

const resilienceProbeMarkerSummaries = {
  'api-ready-before-rollback': 'got HTTP 200; staging artifact; verified markers: ready, service_version, deployment_environment, pre_rollback_version, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'rollback-rollout-artifact': 'got HTTP 200; staging artifact; verified markers: rollout, undo, revision, previous_revision, target_revision, scriptureforge-api, successfully rolled out, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'api-ready-after-rollback': 'got HTTP 200; staging artifact; verified markers: ready, service_version, deployment_environment, post_rollback_version, rolled_back_from, rolled_back_to, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'degradation-drill-artifact': 'got HTTP 200; staging artifact; verified markers: AI, Zoom, degradation, fallback, AI_ORCHESTRATION_ENGINE_FAULT, offline://in-person, non-AI routes healthy, zoom circuit open, distinct_rollback_artifacts=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'backup-snapshot-artifact': 'got HTTP 200; staging artifact; verified markers: snapshot, snapshot_id=snap-123, available, encrypted, kms, retention, automated backup, source cluster, rpo_minutes=15, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'restore-drill-artifact': 'got HTTP 200; staging artifact; verified markers: restore, restore_job_id=restore-456, available, staging, restored endpoint, source snapshot_id=snap-123, checksum, isolated restore, rto_minutes=30, restore_duration_minutes=18, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'restored-database-smoke': 'got HTTP 200; staging artifact; verified markers: smoke passed, restored database, tenant, journal, auth, RLS, migration version, no plaintext journal, distinct_backup_artifacts=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
};

function resilienceProbeReportProbe(name, overrides = {}) {
  const probe = {
    name,
    passed: true,
    target: `https://artifacts.staging.scriptureforge.ai/resilience/${name}.txt`,
    status_code: 200,
    result_summary: resilienceProbeMarkerSummaries[name],
    ...overrides,
  };
  if (name === 'backup-snapshot-artifact') {
    if (!Object.hasOwn(overrides, 'snapshot_id')) {
      probe.snapshot_id = 'snap-123';
    }
    if (!Object.hasOwn(overrides, 'rpo_minutes')) {
      probe.rpo_minutes = 15;
    }
  }
  if (name === 'restore-drill-artifact') {
    if (!Object.hasOwn(overrides, 'restore_job_id')) {
      probe.restore_job_id = 'restore-456';
    }
    if (!Object.hasOwn(overrides, 'source_snapshot_id')) {
      probe.source_snapshot_id = 'snap-123';
    }
    if (!Object.hasOwn(overrides, 'rto_minutes')) {
      probe.rto_minutes = 30;
    }
    if (!Object.hasOwn(overrides, 'restore_duration_minutes')) {
      probe.restore_duration_minutes = 18;
    }
  }
  return probe;
}

function resilienceProbeReportProbes(names, overridesForName = () => ({})) {
  return names.map((name) => resilienceProbeReportProbe(name, overridesForName(name)));
}

const zoomProbeMarkerSummaries = {
  'zoom-oauth-readiness': 'got HTTP 200; staging artifact; verified markers: oauth, account_credentials, status, ok, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'zoom-meeting-create-or-fallback': 'got HTTP 200; staging artifact; verified markers: meeting, join_url, zoom.us, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'zoom-timeout-circuit-fallback': 'got HTTP 200; staging artifact; verified markers: timeout, provider timeout, circuit, open, circuit_open_fallback, fallback, offline://in-person, release_candidate=abc123, service_version=scriptureforge-api:abc123; provider_timeout=true; circuit_open=true; offline_fallback=true',
  'zoom-webhook-signature-delivery': 'got HTTP 200; staging artifact; verified markers: webhook, signature, x-zm-signature=v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, x-zm-request-timestamp=1710000000, stale, replay, 401, invalid, signed, 200, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'zoom-webhook-url-validation': 'got HTTP 200; staging artifact; verified markers: endpoint.url_validation, plain_token=zoom-plain-123, encrypted_token=zoom-encrypted-456, validation_response=200, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'zoom-duplicate-webhook-idempotency': 'got HTTP 200; staging artifact; verified markers: duplicate, x-zm-trackingid, delivery_id=zm-delivery-123, delivery id, same Zoom event, idempotent, 200, single state mutation, no duplicate side effects, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'zoom-meeting-room-mapping': 'got HTTP 200; staging artifact; verified markers: meeting_external_id=zoom-123, live_rooms, internal_room_id=room-abc, redis room state, mapped, unknown meeting ignored, no external meeting id fallback, distinct_zoom_artifacts=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
};

function zoomProbeReportProbe(name, overrides = {}) {
  const probe = {
    name,
    passed: true,
    target: `https://artifacts.staging.scriptureforge.ai/zoom/${name}.txt`,
    status_code: 200,
    result_summary: zoomProbeMarkerSummaries[name],
    ...overrides,
  };
  if (name === 'zoom-duplicate-webhook-idempotency' && !Object.hasOwn(overrides, 'delivery_id')) {
    probe.delivery_id = 'zm-delivery-123';
  }
  if (name === 'zoom-webhook-signature-delivery' && !Object.hasOwn(overrides, 'webhook_signature')) {
    probe.webhook_signature = 'v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  }
  if (name === 'zoom-timeout-circuit-fallback' && !Object.hasOwn(overrides, 'provider_timeout')) {
    probe.provider_timeout = true;
  }
  if (name === 'zoom-timeout-circuit-fallback' && !Object.hasOwn(overrides, 'circuit_open')) {
    probe.circuit_open = true;
  }
  if (name === 'zoom-timeout-circuit-fallback' && !Object.hasOwn(overrides, 'offline_fallback')) {
    probe.offline_fallback = true;
  }
  if (name === 'zoom-webhook-signature-delivery' && !Object.hasOwn(overrides, 'webhook_timestamp')) {
    probe.webhook_timestamp = '1710000000';
  }
  if (name === 'zoom-webhook-url-validation' && !Object.hasOwn(overrides, 'plain_token')) {
    probe.plain_token = 'zoom-plain-123';
  }
  if (name === 'zoom-webhook-url-validation' && !Object.hasOwn(overrides, 'encrypted_token')) {
    probe.encrypted_token = 'zoom-encrypted-456';
  }
  if (name === 'zoom-webhook-url-validation' && !Object.hasOwn(overrides, 'validation_response')) {
    probe.validation_response = '200';
  }
  if (name === 'zoom-meeting-room-mapping' && !Object.hasOwn(overrides, 'meeting_external_id')) {
    probe.meeting_external_id = 'zoom-123';
  }
  if (name === 'zoom-meeting-room-mapping' && !Object.hasOwn(overrides, 'internal_room_id')) {
    probe.internal_room_id = 'room-abc';
  }
  return probe;
}

function zoomProbeReportProbes(names = Object.keys(zoomProbeMarkerSummaries), overridesForName = () => ({})) {
  return names.map((name) => zoomProbeReportProbe(name, overridesForName(name)));
}

const aiProbeMarkerSummaries = {
  'ai-provider-config': 'got HTTP 200; staging artifact; verified markers: AI_PROVIDER, AI_CHAT_MODEL, AI_CHAT_ENDPOINT, AI_HTTP_TIMEOUT_MS, AI_MAX_RETRIES, OPENAI_API_KEY redacted, configured, release_candidate=abc123, service_version=scriptureforge-api:abc123; AI_PROVIDER=openai; AI_CHAT_MODEL=gpt-staging; AI_CHAT_ENDPOINT=https://api.openai.com/v1/chat/completions; AI_HTTP_TIMEOUT_MS=3500; AI_MAX_RETRIES=1',
  'ai-generation-route': 'got HTTP 200; staging artifact; verified markers: /api/v1/ai/generate/study, authenticated, JWT claims, organization_id=org-123, user_id=user-123, request_id=req-123, 200, generated_curriculum, [Genesis 1:1], release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'ai-timeout-degradation': 'got HTTP 200; staging artifact; verified markers: provider timeout, degradation, retry exhausted, 503, fail closed, AI_ORCHESTRATION_ENGINE_FAULT, release_candidate=abc123, service_version=scriptureforge-api:abc123; provider_timeout=true; retry_exhausted=true; fail_closed=true',
  'ai-citation-verification': 'got HTTP 200; staging artifact; verified markers: no-citation rejected, hallucinated citation rejected, verified citation accepted, citation_trails, citation_id=cite-123, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'ai-audit-persistence': 'got HTTP 200; staging artifact; verified markers: ai_request_logs, citation_trails, organization_id=org-123, user_id=user-123, request_id=req-123, citation_id=cite-123, succeeded, failed, verified, tenant rls, cross-tenant hidden, distinct_ai_artifacts=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
};

function aiProbeReportProbe(name, overrides = {}) {
  const probe = {
    name,
    passed: true,
    target: `https://artifacts.staging.scriptureforge.ai/ai/${name}.txt`,
    status_code: 200,
    result_summary: aiProbeMarkerSummaries[name],
    ...overrides,
  };
  if (name === 'ai-provider-config' && !Object.hasOwn(overrides, 'ai_provider')) {
    probe.ai_provider = 'openai';
  }
  if (name === 'ai-provider-config' && !Object.hasOwn(overrides, 'ai_chat_model')) {
    probe.ai_chat_model = 'gpt-staging';
  }
  if (name === 'ai-provider-config' && !Object.hasOwn(overrides, 'ai_chat_endpoint')) {
    probe.ai_chat_endpoint = 'https://api.openai.com/v1/chat/completions';
  }
  if (name === 'ai-provider-config' && !Object.hasOwn(overrides, 'ai_http_timeout_ms')) {
    probe.ai_http_timeout_ms = '3500';
  }
  if (name === 'ai-provider-config' && !Object.hasOwn(overrides, 'ai_max_retries')) {
    probe.ai_max_retries = '1';
  }
  if (name === 'ai-timeout-degradation' && !Object.hasOwn(overrides, 'provider_timeout')) {
    probe.provider_timeout = true;
  }
  if (name === 'ai-timeout-degradation' && !Object.hasOwn(overrides, 'retry_exhausted')) {
    probe.retry_exhausted = true;
  }
  if (name === 'ai-timeout-degradation' && !Object.hasOwn(overrides, 'fail_closed')) {
    probe.fail_closed = true;
  }
  if ((name === 'ai-generation-route' || name === 'ai-audit-persistence') && !Object.hasOwn(overrides, 'request_id')) {
    probe.request_id = 'req-123';
  }
  if ((name === 'ai-generation-route' || name === 'ai-audit-persistence') && !Object.hasOwn(overrides, 'organization_id')) {
    probe.organization_id = 'org-123';
  }
  if ((name === 'ai-generation-route' || name === 'ai-audit-persistence') && !Object.hasOwn(overrides, 'user_id')) {
    probe.user_id = 'user-123';
  }
  if ((name === 'ai-citation-verification' || name === 'ai-audit-persistence') && !Object.hasOwn(overrides, 'citation_id')) {
    probe.citation_id = 'cite-123';
  }
  return probe;
}

function aiProbeReportProbes(names = Object.keys(aiProbeMarkerSummaries), overridesForName = () => ({})) {
  return names.map((name) => aiProbeReportProbe(name, overridesForName(name)));
}

const abuseProbeMarkerSummaries = {
  'auth-rate-limit': 'got 429 with headers after 2 attempts; verified markers: staging artifact, auth-rate-limit, 429, after, attempts, repeated_attempts_verified=true, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'auth-account-rate-limit': 'got 429 with headers after 2 attempts; verified markers: staging artifact, auth-account-rate-limit, 429, after, attempts, repeated_attempts_verified=true, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, account-scoped login, account_scoped=true, rotating forwarded client IP, forwarded_client_ip_rotated=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'auth-refresh-rate-limit': 'got 429 with headers after 2 attempts; verified markers: staging artifact, auth-refresh-rate-limit, 429, after, attempts, repeated_attempts_verified=true, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, refresh token, refresh_token_scoped=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'ai-rate-limit': 'got 429 with headers after 2 attempts; verified markers: staging artifact, ai-rate-limit, 429, after, attempts, repeated_attempts_verified=true, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'journal-rate-limit': 'got 429 with headers after 2 attempts; verified markers: staging artifact, journal-rate-limit, 429, after, attempts, repeated_attempts_verified=true, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'rooms-rate-limit': 'got 429 with headers after 2 attempts; verified markers: staging artifact, rooms-rate-limit, 429, after, attempts, repeated_attempts_verified=true, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'websocket-rate-limit': 'got 429 with headers after 2 attempts; verified markers: staging artifact, websocket-rate-limit, 429, after, attempts, repeated_attempts_verified=true, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, websocket upgrade, websocket_upgrade=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
};

const abuseProbeNames = ['auth-rate-limit', 'auth-account-rate-limit', 'auth-refresh-rate-limit', 'ai-rate-limit', 'journal-rate-limit', 'rooms-rate-limit', 'websocket-rate-limit'];

const abuseConfigSummary = 'config artifact verified markers: staging artifact, ABUSE_LIMIT_AUTH_REQUESTS=2, ABUSE_LIMIT_AUTH_WINDOW_SECONDS=60, ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=2, ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=60, ABUSE_LIMIT_AI_REQUESTS=2, ABUSE_LIMIT_JOURNAL_REQUESTS=2, ABUSE_LIMIT_ROOMS_REQUESTS=2, ABUSE_LIMIT_WEBSOCKET_REQUESTS=2, ABUSE_LIMIT_MAX_BUCKETS=1000, TRUST_PROXY_HEADERS=true, X-Forwarded-For, X-Real-IP, redacted, release_candidate=abc123, service_version=scriptureforge-api:abc123, distinct_abuse_artifacts=true';

function abuseProbeStructuredFields(name) {
  return {
    ...(name === 'auth-account-rate-limit' ? { account_scoped: true, forwarded_client_ip_rotated: true } : {}),
    ...(name === 'auth-refresh-rate-limit' ? { refresh_token_scoped: true } : {}),
    ...(name === 'websocket-rate-limit' ? { websocket_upgrade: true } : {}),
  };
}

function abuseProbeReportProbe(name, overrides = {}) {
  return {
    name,
    passed: true,
    status_code: 429,
    attempts: 2,
    retry_after: '60',
    rate_limit: '1',
    rate_limit_remaining: '0',
    rate_limit_reset: '1782403200',
    ...abuseProbeStructuredFields(name),
    result_summary: abuseProbeMarkerSummaries[name],
    ...overrides,
  };
}

function abuseProbeReportProbes(overridesForName = () => ({})) {
  return abuseProbeNames.map((name) => abuseProbeReportProbe(name, overridesForName(name)));
}

const mobileProbeMarkerSummaries = {
  'mobile-eas-or-device-run': 'got HTTP 200; verified markers: staging artifact, eas, build, finished, android, ios, native device, installed app, release channel staging, expo profile staging, platforms=android,ios, release_channel=staging, expo_profile=staging, release_candidate=abc123, service_version=scriptureforge-mobile:abc123, distinct_mobile_artifacts=true',
  'mobile-native-crypto-smoke': 'got HTTP 200; verified markers: staging artifact, runJournalCryptoSelfTest, react-native-quick-crypto, native provider, native module loaded, provider status react-native-quick-crypto, provider=react-native-quick-crypto, native-required true, native_required=true, AES-GCM, round-trip, unique_iv=true, unique IV, tamper rejected, associated data, wrong associated data rejected, associated_data_salt_id=journal:self-test:server-derived-salt, associated_data_salt_version=1, non-extractable, provider-bound key, fallback-derived key rejected, key disposed, disposed handle rejected, passphrase wiped, passphrase buffer zeroized, salt wiped, salt buffer zeroized, plaintext cleared, plaintext buffer zeroized, release_candidate=abc123, service_version=scriptureforge-mobile:abc123, distinct_mobile_artifacts=true',
  'mobile-staging-config': 'got HTTP 200; verified markers: staging artifact, EXPO_PUBLIC_API_BASE_URL, EXPO_PUBLIC_WS_BASE_URL, EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true, EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging, https://, wss://, staging, EXPO_PUBLIC_API_BASE_URL=https://api.staging.scriptureforge.ai, EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.scriptureforge.ai, release_candidate=abc123, service_version=scriptureforge-mobile:abc123, distinct_mobile_artifacts=true',
};

function mobileEASProbe(overrides = {}) {
  return {
    name: 'mobile-eas-or-device-run',
    passed: true,
    target: 'https://artifacts.staging.scriptureforge.ai/mobile/eas-build.txt',
    status_code: 200,
    platforms: 'android,ios',
    release_channel: 'staging',
    expo_profile: 'staging',
    result_summary: mobileProbeMarkerSummaries['mobile-eas-or-device-run'],
    ...overrides,
  };
}

function mobileConfigProbe(overrides = {}) {
  return {
    name: 'mobile-staging-config',
    passed: true,
    target: 'https://artifacts.staging.scriptureforge.ai/mobile/staging-config.txt',
    status_code: 200,
    api_base_url: 'https://api.staging.scriptureforge.ai',
    ws_base_url: 'wss://api.staging.scriptureforge.ai',
    require_native_crypto: 'true',
    deployment_environment: 'staging',
    result_summary: mobileProbeMarkerSummaries['mobile-staging-config'],
    ...overrides,
  };
}

const rustProbeMarkerSummaries = {
  'rust-grpc-health': 'gRPC health status SERVING in 12ms; verified markers: staging artifact, grpc health, scriptureforge.engine.ScriptureEngine, SERVING, release_candidate=abc123, service_version=scriptureforge-rust-engine:abc123, deployment_environment=staging',
  'rust-metrics': 'metrics HTTP 200 in 12ms; verified markers: staging artifact, scriptureforge_rust_engine_embedding_requests_total, scriptureforge_rust_engine_embedding_failures_total, scriptureforge_rust_engine_vector_search_requests_total, scriptureforge_rust_engine_vector_search_failures_total, release_candidate=abc123, service_version=scriptureforge-rust-engine:abc123, deployment_environment=staging, Prometheus metrics, rust_metrics_samples_verified=true, rust_embedding_requests_positive=true, rust_vector_search_requests_positive=true; embedding_requests=1; vector_search_requests=1',
  'api-rust-integration-metrics': 'API metrics HTTP 200 in 12ms; verified markers: staging artifact, Go API rust_engine vector_search success, scriptureforge_dependency_operations_total, scriptureforge_dependency_operation_duration_seconds_sum, api_rust_metrics_samples_verified=true, distinct_metrics_targets=true, release_candidate=abc123, service_version=scriptureforge-rust-engine:abc123, deployment_environment=staging; api_rust_vector_search_ops=1; api_rust_vector_search_seconds=0.042',
};

function rustProbe(name, overrides = {}) {
  const targets = {
    'rust-grpc-health': 'scriptureforge-rust-engine.staging.internal:50051',
    'rust-metrics': 'https://rust-metrics.staging.scriptureforge.ai/metrics',
    'api-rust-integration-metrics': 'https://api.staging.scriptureforge.ai/metrics',
  };
  return {
    name,
    passed: true,
    target: targets[name],
    ...(name === 'rust-grpc-health' ? { status: 'SERVING' } : { status_code: 200 }),
    ...(name === 'rust-metrics' ? { embedding_requests: 1, vector_search_requests: 1 } : {}),
    ...(name === 'api-rust-integration-metrics' ? { api_rust_vector_search_ops: 1, api_rust_vector_search_seconds: 0.042 } : {}),
    result_summary: rustProbeMarkerSummaries[name],
    ...overrides,
  };
}

const observabilityProbeMarkerSummaries = {
  'collector-otlp-config': 'got HTTP 200; verified markers: staging artifact, receivers, otlp, 4317, 4318, exporters, service, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'api-prometheus-metrics': 'got HTTP 200; verified markers: staging artifact, scriptureforge_http_requests_total, scriptureforge_http_request_duration_seconds_sum, scriptureforge_http_requests_total{, status=, websocket_active_connections_count, scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped", ai_inference_duration_seconds_sum, ai_inference_duration_seconds_count, scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success", scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success", release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'rust-prometheus-metrics': 'got HTTP 200; verified markers: staging artifact, scriptureforge_rust_engine_embedding_requests_total, scriptureforge_rust_engine_embedding_failures_total, scriptureforge_rust_engine_vector_search_requests_total, scriptureforge_rust_engine_vector_search_failures_total, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'trace-backend-search': 'got HTTP 200; verified markers: staging artifact, 11112222333344445555666677778888, scriptureforge-api, scriptureforge-rust-engine, route=/api/v1/ai/generate/study, method=POST, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'log-backend-trace-correlation': 'got HTTP 200; verified markers: staging artifact, 11112222333344445555666677778888, trace_id, scriptureforge-api, scriptureforge-rust-engine, route=/api/v1/ai/generate/study, method=POST, service_version, deployment_environment, tenant_id=org-staging, user_id=user-staging, role=admin, distinct_otel_artifacts=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'dashboard-import': 'got HTTP 200; verified markers: staging artifact, ScriptureForge, scriptureforge_http_requests_total, scriptureforge_http_request_duration_seconds_sum, websocket_active_connections_count, room_broadcast, ai_inference_duration_seconds, scriptureforge_rust_engine_, trace_id, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'alert-rules-loaded': 'got HTTP 200; verified markers: staging artifact, ScriptureForgeHighErrorRate, ScriptureForgeTrafficAbsent, ScriptureForgeAuthFailureSpike, ScriptureForgeAbuseLimitSpike, ScriptureForgeRouteLatencyElevated, ScriptureForgeDependencyFailures, ScriptureForgeAIInferenceLatencyElevated, ScriptureForgeJournalWriteFailures, ScriptureForgeRoomStreamFailures, ScriptureForgeRoomBroadcastDrops, ScriptureForgeRustEngineFailures, scriptureforge_http_requests_total, scriptureforge_dependency_operations_total, ai_inference_duration_seconds, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'alert-delivery-status': 'got HTTP 200; verified markers: staging artifact, success, delivered, test alert, alertmanager, delivery_id=am-delivery-123, alertname=ScriptureForgeHighErrorRate, receiver=staging-release, release_candidate=abc123, service_version=scriptureforge-api:abc123',
  'telemetry-retention-policy': 'got HTTP 200; verified markers: staging artifact, retention, 30 days, trace, logs, metrics, distinct_alert_artifacts=true, release_candidate=abc123, service_version=scriptureforge-api:abc123',
};

const observabilityTraceID = '11112222333344445555666677778888';
function observabilityProbeTarget(name) {
  if (name === 'trace-backend-search') {
    return `https://traces.staging.scriptureforge.ai/search?trace_id=${observabilityTraceID}`;
  }
  if (name === 'log-backend-trace-correlation') {
    return `https://logs.staging.scriptureforge.ai/search?trace_id=${observabilityTraceID}`;
  }
  return `https://observability.staging.scriptureforge.ai/${name}`;
}

function observabilityProbeReportProbe(name, overrides = {}) {
  const probe = {
    name,
    passed: true,
    target: observabilityProbeTarget(name),
    status_code: 200,
    result_summary: observabilityProbeMarkerSummaries[name],
    ...overrides,
  };
  if (name === 'alert-delivery-status' && !Object.hasOwn(overrides, 'delivery_id')) {
    probe.delivery_id = 'am-delivery-123';
  }
  if (name === 'alert-delivery-status' && !Object.hasOwn(overrides, 'alert_name')) {
    probe.alert_name = 'ScriptureForgeHighErrorRate';
  }
  if (name === 'alert-delivery-status' && !Object.hasOwn(overrides, 'alert_receiver')) {
    probe.alert_receiver = 'staging-release';
  }
  if ((name === 'trace-backend-search' || name === 'log-backend-trace-correlation') && !Object.hasOwn(overrides, 'trace_id')) {
    probe.trace_id = observabilityTraceID;
  }
  if ((name === 'trace-backend-search' || name === 'log-backend-trace-correlation') && !Object.hasOwn(overrides, 'observed_route')) {
    probe.observed_route = '/api/v1/ai/generate/study';
  }
  if ((name === 'trace-backend-search' || name === 'log-backend-trace-correlation') && !Object.hasOwn(overrides, 'http_method')) {
    probe.http_method = 'POST';
  }
  if (name === 'log-backend-trace-correlation' && !Object.hasOwn(overrides, 'tenant_id')) {
    probe.tenant_id = 'org-staging';
  }
  if (name === 'log-backend-trace-correlation' && !Object.hasOwn(overrides, 'user_id')) {
    probe.user_id = 'user-staging';
  }
  if (name === 'log-backend-trace-correlation' && !Object.hasOwn(overrides, 'role')) {
    probe.role = 'admin';
  }
  return probe;
}

function observabilityProbeReportProbes(names = Object.keys(observabilityProbeMarkerSummaries), overridesForName = () => ({})) {
  return names.map((name) => observabilityProbeReportProbe(name, overridesForName(name)));
}

const performanceReportSummaries = {
  http: 'profile=staging_http target=https://api.staging.scriptureforge.ai/health concurrency=500 duration_ms=60000 duration_ms>=60000 min_rps=5000 max_p99_ms=200 production_target_rps=5000 production_target_p99_ms=200 production_min_duration_ms=60000 observed_rps=5200 observed_p99_ms=180 threshold_pass=true http_replica_count=2 dependency_postgres_p99_ms=32 dependency_redis_p99_ms=18 release_candidate=abc123 service_version=scriptureforge-api:abc123; verified markers: staging_http, https://, min_rps, 5000, max_p99_ms, 200, observed_rps, observed_p99_ms, release_candidate, service_version, http_replica_artifact_url, http_replica_artifact_verified, http_replica_count=2, dependency_telemetry_artifact_url, dependency_telemetry_artifact_verified, dependency_latency_artifact_verified=true, dependency_postgres_p99_ms=32, dependency_redis_p99_ms=18, http_distinct_artifacts=true',
  websocket: 'staging artifact profile=staging_websocket target=wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1 concurrency=500 duration_ms=60000 duration_ms>=60000 min_rps=500 max_p99_ms=200 production_target_rps=500 production_target_p99_ms=200 production_min_duration_ms=60000 observed_rps=620 observed_p99_ms=140 threshold_pass=true release_candidate=abc123 service_version=scriptureforge-api:abc123 production_min_ws_events=30000 ws_origin=https://web.staging.scriptureforge.ai ws_room_id=room-1 ws_authenticated=true ws_expected_events=30000 ws_unique_sequences=30000 ws_min_sequence=1 ws_max_sequence=30000 ws_polling_latest_sequence=30000 ws_sequence_contiguous=true ws_replica_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt ws_reconnect_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt redis_telemetry_artifact_url=https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt ws_replica_count=2 room_broadcast_drops=0; verified markers: staging artifact, staging_websocket, wss://, min_rps, 500, max_p99_ms, 200, observed_rps, observed_p99_ms, release_candidate, service_version, ws_sequence_contiguous=true, ws_origin=https://, ws_room_id, ws_authenticated=true, ws_expected_events, ws_unique_sequences, ws_min_sequence, ws_max_sequence, ws_polling_latest_sequence, redis_telemetry_artifact_url=https://, ws_replica_artifact_url=https://, ws_replica_artifact_verified, ws_replica_count=2, ws_reconnect_artifact_url=https://, ws_reconnect_artifact_verified, ws_reconnect_sequence_continues=true, ws_polling_artifact_url=https://, ws_polling_artifact_verified, ws_polling_artifact_latest_sequence_validated=true, ws_polling_artifact_latest_sequence_matches_run=true, redis_telemetry_artifact_verified, ws_distinct_artifacts=true, room_broadcast_drops=0',
};

function httpPerformanceReport(overrides = {}) {
  return {
    observed_at: '2026-06-25T12:00:00Z',
    threshold_pass: true,
    evidence_items: ['PERF-HTTP-001'],
    evidence_profile: 'staging_http',
    target: 'https://api.staging.scriptureforge.ai/health',
    min_rps: 5000,
    max_p99_ms: 200,
    production_target_rps: 5000,
    production_target_p99_ms: 200,
    production_min_duration_ms: 60000,
    release_candidate: 'abc123',
    service_version: 'scriptureforge-api:abc123',
    threshold_failures: [],
    duration_ms: 60000,
    rps: 5200,
    p99_ms: 180,
    http_replica_count: 2,
    dependency_postgres_p99_ms: 32,
    dependency_redis_p99_ms: 18,
    http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
    dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
    result_summary: performanceReportSummaries.http,
    ...overrides,
  };
}

function websocketPerformanceReport(overrides = {}) {
  return {
    observed_at: '2026-06-25T12:00:00Z',
    threshold_pass: true,
    evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
    evidence_profile: 'staging_websocket',
    target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
    min_rps: 500,
    max_p99_ms: 200,
    production_target_rps: 500,
    production_target_p99_ms: 200,
    production_min_duration_ms: 60000,
    production_min_ws_events: 30000,
    release_candidate: 'abc123',
    service_version: 'scriptureforge-api:abc123',
    threshold_failures: [],
    duration_ms: 60000,
    rps: 620,
    p99_ms: 140,
    ws_origin: 'https://web.staging.scriptureforge.ai',
    ws_room_id: 'room-1',
    ws_authenticated: true,
    ws_expected_events: 30000,
    ws_unique_sequences: 30000,
    ws_min_sequence: 1,
    ws_max_sequence: 30000,
    ws_polling_latest_sequence: 30000,
    ws_sequence_contiguous: true,
    ws_replica_count: 2,
    room_broadcast_drops: 0,
    ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
    ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
    ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
    redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
    result_summary: performanceReportSummaries.websocket,
    ...overrides,
  };
}

test('parseArgs requires the manifest, report, artifact, and command', () => {
  assert.throws(
    () => parseArgs(['--manifest', 'manifest.json']),
    /missing --probe-report or --item-id/,
  );
  assert.throws(
    () => parseArgs(['--manifest', 'manifest.json', '--artifact', 'artifact.json', '--command', 'probe']),
    /missing --probe-report or --item-id/,
  );
  assert.throws(
    () => parseArgs(['--manifest', 'manifest.json', '--probe-report', 'probe.json', '--item-id', 'DEPLOY-TF-001', '--artifact', 'artifact.json', '--command', 'probe']),
    /choose only one/,
  );
  assert.throws(
    () => parseArgs(['--manifest', 'manifest.json', '--item-id', 'DEPLOY-TF-001', '--artifact', 'artifact.json', '--command', 'terraform plan']),
    /missing --summary/,
  );
  assert.throws(
    () => parseArgs(['--manifest', 'manifest.json', '--item-id', 'DEPLOY-TF-001', '--status', 'blocked']),
    /requires --owner and --blocker/,
  );
  assert.throws(
    () => parseArgs(['--manifest', 'manifest.json', '--item-id', 'SEC-SIGNOFF-001', '--status', 'accepted_risk']),
    /requires --decision-ref/,
  );
});
test('summarizeProbeReport captures passed and failed probes', () => {
  const summary = summarizeProbeReport({
    probes: [
      { name: 'api-live', passed: true },
      { name: 'api-ready', passed: false },
    ],
  });
  assert.equal(summary, '1 probes passed, 1 probes failed (api-live:pass, api-ready:fail)');
});
test('recordEvidence marks referenced manifest items as passed with artifact details', () => {
  const manifest = {
    schema_version: 1,
    environment: 'staging',
    release_candidate: 'abc123',
    generated_at: '2026-06-25T00:00:00Z',
    items: [
      {
        id: 'DEPLOY-TLS-001',
        category: 'deployment',
        status: 'pending_external',
        description: 'TLS proof',
        required_evidence: ['probe'],
      },
      {
        id: 'CLIENT-WEB-001',
        category: 'client',
        status: 'pending_external',
        description: 'Web proof',
        required_evidence: ['probe'],
      },
    ],
  };
  const report = {
    observed_at: '2026-06-25T12:00:00Z',
    threshold_pass: true,
    evidence_items: ['DEPLOY-TLS-001', 'CLIENT-WEB-001'],
    release_candidate: 'abc123',
    service_version: 'scriptureforge-web:abc123',
    dns_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/dns.txt',
    acm_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/acm.txt',
    web_target: 'https://app.staging.scriptureforge.ai',
    web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
    web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
    web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
    probes: [
      { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
      { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
      { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
      ...webSmokeProbes('abc123', 'scriptureforge-web:abc123'),
    ],
  };

  const updated = recordEvidence(manifest, report, 'artifacts/stagingprobe.json', 'go run ./tools/stagingprobe');

  for (const item of updated.items) {
    assert.equal(item.status, 'passed');
    assert.equal(item.evidence.length, 1);
    assert.equal(item.evidence[0].artifact, 'artifacts/stagingprobe.json');
    assert.equal(item.evidence[0].command_or_probe, 'go run ./tools/stagingprobe');
    assert.match(item.evidence[0].result_summary, /6 probes passed/);
  }
});

test('recordEvidence records production-grade CI release evidence', () => {
  const manifest = {
    release_candidate: '0123456789abcdef0123456789abcdef01234567',
    items: [{ id: 'SRC-CI-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      commit_sha: '0123456789abcdef0123456789abcdef01234567',
      workflow_name: 'Security Pipeline Verification',
      repository: 'example/scriptureforgeai',
      ref: 'refs/heads/main',
      ref_name: 'main',
      event_name: 'push',
      source_control_status: 'clean',
      release_evidence_scope: 'exact-github-sha-required-gates',
      ci_run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
      evidence_items: ['SRC-CI-001'],
      probes: [
        {
          name: 'github-actions-release-run',
          passed: true,
          target: 'https://artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt',
          run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
          repository: 'example/scriptureforgeai',
          ref: 'refs/heads/main',
          ref_name: 'main',
          event_name: 'push',
          source_control_status: 'clean',
          release_evidence_scope: 'exact-github-sha-required-gates',
          result_summary: ciReleaseEvidenceProofSummary(),
        },
      ],
    },
    'artifacts/ciprobe.json',
    'go run ./tools/ciprobe -run-artifact-url https://artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.match(updated.items[0].evidence[0].result_summary, /release_candidate=0123456789abcdef0123456789abcdef01234567/);
  assert.match(updated.items[0].evidence[0].result_summary, /local_gate_markers_included=true/);
});

function ciReleaseEvidenceProofSummary() {
  return `proof markers: ${ciReleaseEvidenceProofMarkers.join(', ')}`;
}

function ciReleaseEvidenceReport(probeOverrides = {}) {
  return {
    observed_at: '2026-06-25T12:00:00Z',
    threshold_pass: true,
    commit_sha: '0123456789abcdef0123456789abcdef01234567',
    workflow_name: 'Security Pipeline Verification',
    repository: 'example/scriptureforgeai',
    ref: 'refs/heads/main',
    ref_name: 'main',
    event_name: 'push',
    source_control_status: 'clean',
    release_evidence_scope: 'exact-github-sha-required-gates',
    ci_run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
    evidence_items: ['SRC-CI-001'],
    probes: [
      {
        name: 'github-actions-release-run',
        passed: true,
        target: 'https://artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt',
        run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
        repository: 'example/scriptureforgeai',
        ref: 'refs/heads/main',
        ref_name: 'main',
        event_name: 'push',
        source_control_status: 'clean',
        release_evidence_scope: 'exact-github-sha-required-gates',
        result_summary: ciReleaseEvidenceProofSummary(),
        ...probeOverrides,
      },
    ],
  };
}

test('recordEvidence rejects CI release evidence from a local artifact target', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: '0123456789abcdef0123456789abcdef01234567',
        items: [{ id: 'SRC-CI-001', status: 'pending_external' }],
      },
      ciReleaseEvidenceReport({ target: 'artifacts/ci-release-evidence.txt' }),
      'artifacts/ciprobe.json',
      'go run ./tools/ciprobe -run-artifact-file artifacts/ci-release-evidence.txt',
    ),
    /github-actions-release-run target must be an uploaded HTTPS ci-release-evidence artifact URL/,
  );
});

test('recordEvidence rejects CI evidence without release proof markers', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: '0123456789abcdef0123456789abcdef01234567',
        items: [{ id: 'SRC-CI-001', status: 'pending_external' }],
      },
      ciReleaseEvidenceReport({
        result_summary: ciReleaseEvidenceProofSummary().replace('local_gate_markers_included=true, ', ''),
      }),
      'artifacts/ciprobe.json',
      'go run ./tools/ciprobe -run-artifact-file artifacts/ci-release-evidence.txt',
    ),
    /SRC-CI-001 result_summary must include verified marker local_gate_markers_included=true/,
  );
});

test('recordEvidence rejects CI evidence for a different release candidate', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: '0123456789abcdef0123456789abcdef01234567',
        items: [{ id: 'SRC-CI-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        commit_sha: 'fedcba9876543210fedcba9876543210fedcba98',
        workflow_name: 'Security Pipeline Verification',
        repository: 'example/scriptureforgeai',
        ref: 'refs/heads/main',
        ref_name: 'main',
        event_name: 'push',
        source_control_status: 'clean',
        release_evidence_scope: 'exact-github-sha-required-gates',
        ci_run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
        evidence_items: ['SRC-CI-001'],
        probes: [
          {
            name: 'github-actions-release-run',
            passed: true,
            target: 'artifacts/ci-release-evidence.txt',
            run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
            repository: 'example/scriptureforgeai',
            ref: 'refs/heads/main',
            ref_name: 'main',
            event_name: 'push',
            source_control_status: 'clean',
            release_evidence_scope: 'exact-github-sha-required-gates',
          },
        ],
      },
      'artifacts/ciprobe.json',
      'go run ./tools/ciprobe -run-artifact-file artifacts/ci-release-evidence.txt',
    ),
    /SRC-CI-001 report commit_sha must match manifest release_candidate/,
  );
});

test('recordEvidence rejects CI evidence without GitHub run identity', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SRC-CI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        commit_sha: '0123456789abcdef0123456789abcdef01234567',
        workflow_name: 'Security Pipeline Verification',
        repository: 'example/scriptureforgeai',
        ref: 'refs/heads/main',
        ref_name: 'main',
        event_name: 'push',
        source_control_status: 'clean',
        release_evidence_scope: 'exact-github-sha-required-gates',
        evidence_items: ['SRC-CI-001'],
        probes: [{ name: 'github-actions-release-run', passed: true }],
      },
      'artifacts/ciprobe.json',
      'go run ./tools/ciprobe',
    ),
    /must include GitHub Actions ci_run_url/,
  );
});

test('recordEvidence rejects CI evidence without source-control provenance', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SRC-CI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        commit_sha: '0123456789abcdef0123456789abcdef01234567',
        workflow_name: 'Security Pipeline Verification',
        repository: 'example/scriptureforgeai',
        ref: 'refs/heads/main',
        ref_name: 'main',
        event_name: 'push',
        source_control_status: 'dirty',
        release_evidence_scope: 'exact-github-sha-required-gates',
        ci_run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
        evidence_items: ['SRC-CI-001'],
        probes: [
          {
            name: 'github-actions-release-run',
            passed: true,
            target: 'artifacts/ci-release-evidence.txt',
            run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
            repository: 'example/scriptureforgeai',
            ref: 'refs/heads/main',
            ref_name: 'main',
            event_name: 'push',
            source_control_status: 'dirty',
            release_evidence_scope: 'exact-github-sha-required-gates',
          },
        ],
      },
      'artifacts/ciprobe.json',
      'go run ./tools/ciprobe',
    ),
    /source_control_status=clean/,
  );
});

test('recordEvidence rejects web client evidence without browser smoke artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-WEB-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-WEB-001'],
        web_target: 'https://app.staging.scriptureforge.ai',
        probes: [
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /must include HTTPS web_auth_smoke_url/,
  );
});

test('recordEvidence rejects web client evidence with reused browser smoke artifact URLs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-WEB-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-WEB-001'],
        web_target: 'https://app.staging.scriptureforge.ai',
        web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
        probes: [
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
          {
            name: 'web-auth-browser-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
            status_code: 200,
            result_summary: webSmokeProbeMarkerSummaries['web-auth-browser-smoke'],
          },
          {
            name: 'web-journal-browser-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
            status_code: 200,
            result_summary: webSmokeProbeMarkerSummaries['web-journal-browser-smoke'],
          },
          {
            name: 'web-room-browser-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
            status_code: 200,
            result_summary: webSmokeProbeMarkerSummaries['web-room-browser-smoke'],
          },
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /CLIENT-WEB-001 web_journal_smoke_url must be a distinct artifact URL from web_auth_smoke_url/,
  );
});

test('recordEvidence records production-grade tenant RLS evidence', () => {
  const manifest = {
    items: [{ id: 'DATA-RLS-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    tenantRLSProbeReport(),
    'artifacts/tenantprobe.json',
    'go run ./tools/tenantprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects tenant RLS evidence without concrete DB role bypass proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001', status: 'pending_external' }] },
      tenantRLSProbeReport({
        'database-rls-context-proof': {
          result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary.replace('bypassrls=false, ', '')}`,
        },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /database-rls-context-proof result_summary must include verified marker bypassrls=false/,
  );
});

test('recordEvidence rejects tenant RLS evidence without API proof summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        api_target: 'https://api.staging.scriptureforge.ai',
        owner_org_id: '11111111-1111-4111-8111-111111111111',
        blocked_org_id: '22222222-2222-4222-8222-222222222222',
        evidence_items: ['DATA-RLS-001'],
        probes: [
          { name: 'owner-create-encrypted-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 201, result_summary: 'create returned HTTP 201' },
          { name: 'blocked-journal-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-journal-tenant-override-write-denied'] },
          { name: 'owner-read-created-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['owner-read-created-journal'] },
          { name: 'owner-list-contains-created-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['owner-list-contains-created-journal'] },
          { name: 'blocked-read-created-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 404, result_summary: tenantAPIProbeMarkerSummaries['blocked-read-created-journal'] },
          { name: 'blocked-list-excludes-created-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['blocked-list-excludes-created-journal'] },
          { name: 'owner-create-room', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 201, result_summary: tenantAPIProbeMarkerSummaries['owner-create-room'] },
          { name: 'blocked-room-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-room-tenant-override-write-denied'] },
          { name: 'owner-active-rooms-contains-created-room', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['owner-active-rooms-contains-created-room'] },
          { name: 'blocked-active-rooms-excludes-created-room', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['blocked-active-rooms-excludes-created-room'] },
          { name: 'owner-room-state', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['owner-room-state'] },
          { name: 'blocked-room-state-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 403, result_summary: tenantAPIProbeMarkerSummaries['blocked-room-state-denied'] },
          {
            name: 'database-rls-context-proof',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/data/rls-db-proof.txt',
            status_code: 200,
            result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary}`,
          },
        ],
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /owner-create-encrypted-journal result_summary must include verified marker same-tenant journal write accepted/,
  );
});

test('recordEvidence rejects tenant RLS evidence without same-tenant journal list proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        api_target: 'https://api.staging.scriptureforge.ai',
        owner_org_id: '11111111-1111-4111-8111-111111111111',
        blocked_org_id: '22222222-2222-4222-8222-222222222222',
        evidence_items: ['DATA-RLS-001'],
        probes: [
          tenantAPIProbe('owner-create-encrypted-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 201 }),
          { name: 'blocked-journal-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-journal-tenant-override-write-denied'] },
          { name: 'owner-read-created-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['owner-read-created-journal'] },
          { name: 'blocked-read-created-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 404, result_summary: tenantAPIProbeMarkerSummaries['blocked-read-created-journal'] },
          { name: 'blocked-list-excludes-created-journal', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['blocked-list-excludes-created-journal'] },
          { name: 'owner-create-room', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 201, result_summary: tenantAPIProbeMarkerSummaries['owner-create-room'] },
          { name: 'blocked-room-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-room-tenant-override-write-denied'] },
          { name: 'owner-active-rooms-contains-created-room', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['owner-active-rooms-contains-created-room'] },
          { name: 'blocked-active-rooms-excludes-created-room', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['blocked-active-rooms-excludes-created-room'] },
          { name: 'owner-room-state', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 200, result_summary: tenantAPIProbeMarkerSummaries['owner-room-state'] },
          { name: 'blocked-room-state-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 403, result_summary: tenantAPIProbeMarkerSummaries['blocked-room-state-denied'] },
          {
            name: 'database-rls-context-proof',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/data/rls-db-proof.txt',
            status_code: 200,
            result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary}`,
          },
        ],
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /DATA-RLS-001 report must include exactly the required tenant isolation probes/,
  );
});

test('recordEvidence rejects tenant RLS evidence without deployed API and DB proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        api_target: 'http://localhost:8080',
        owner_org_id: '11111111-1111-4111-8111-111111111111',
        blocked_org_id: '22222222-2222-4222-8222-222222222222',
        evidence_items: ['DATA-RLS-001'],
        probes: [
          { name: 'owner-create-encrypted-journal', passed: true },
          { name: 'blocked-journal-tenant-override-write-denied', passed: true },
          { name: 'owner-read-created-journal', passed: true },
          { name: 'blocked-read-created-journal', passed: true },
          { name: 'blocked-list-excludes-created-journal', passed: true },
          { name: 'owner-create-room', passed: true },
          { name: 'blocked-room-tenant-override-write-denied', passed: true },
          { name: 'owner-active-rooms-contains-created-room', passed: true },
          { name: 'blocked-active-rooms-excludes-created-room', passed: true },
          { name: 'owner-room-state', passed: true },
          { name: 'blocked-room-state-denied', passed: true },
          { name: 'database-rls-context-proof', passed: true, target: 'http://localhost/rls.txt', status_code: 200 },
        ],
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /must use HTTPS api_target/,
  );
});

test('recordEvidence rejects tenant RLS evidence without structured tenant pair', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        ...tenantRLSProbeReport(),
        owner_org_id: '',
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /DATA-RLS-001 report must include UUID owner_org_id/,
  );

  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        ...tenantRLSProbeReport(),
        owner_org_id: 'owner-org',
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /DATA-RLS-001 report must include UUID owner_org_id/,
  );

  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        ...tenantRLSProbeReport(),
        blocked_org_id: '11111111-1111-4111-8111-111111111111',
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /DATA-RLS-001 owner_org_id and blocked_org_id must be different/,
  );
});

test('recordEvidence rejects tenant RLS evidence whose DB proof is not bound to the owner org', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'database-rls-context-proof': {
          result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary.replace('app.current_org_id=11111111-1111-4111-8111-111111111111', 'app.current_org_id=33333333-3333-4333-8333-333333333333')}`,
        },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /database-rls-context-proof result_summary must include verified marker app.current_org_id=11111111-1111-4111-8111-111111111111/,
  );
});

test('recordEvidence rejects tenant RLS DB proof hosted on a canonical API target host alias', () => {
  const report = tenantRLSProbeReport({
    'database-rls-context-proof': {
      target: 'https://API.Staging.ScriptureForge.AI./data/rls-db-proof.txt',
    },
  });

  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      report,
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /database-rls-context-proof must use a distinct host from api_target/,
  );
});

test('recordEvidence rejects tenant RLS evidence without cross-tenant denial status', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        api_target: 'https://api.staging.scriptureforge.ai',
        owner_org_id: '11111111-1111-4111-8111-111111111111',
        blocked_org_id: '22222222-2222-4222-8222-222222222222',
        evidence_items: ['DATA-RLS-001'],
        probes: [
          tenantAPIProbe('owner-create-encrypted-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 201 }),
          { name: 'blocked-journal-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-journal-tenant-override-write-denied'] },
          tenantAPIProbe('owner-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 200 }),
          tenantAPIProbe('owner-list-contains-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
          tenantAPIProbe('blocked-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 200 }),
          tenantAPIProbe('blocked-list-excludes-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
          tenantAPIProbe('owner-create-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 201 }),
          { name: 'blocked-room-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-room-tenant-override-write-denied'] },
          tenantAPIProbe('owner-active-rooms-contains-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
          tenantAPIProbe('blocked-active-rooms-excludes-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
          tenantAPIProbe('owner-room-state', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 200 }),
          tenantAPIProbe('blocked-room-state-denied', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 403 }),
          {
            name: 'database-rls-context-proof',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/data/rls-db-proof.txt',
            status_code: 200,
            result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary}`,
          },
        ],
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /blocked-read-created-journal must return HTTP 404/,
  );
});

test('recordEvidence rejects tenant RLS evidence without all DB context markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        api_target: 'https://api.staging.scriptureforge.ai',
        owner_org_id: '11111111-1111-4111-8111-111111111111',
        blocked_org_id: '22222222-2222-4222-8222-222222222222',
        evidence_items: ['DATA-RLS-001'],
        probes: [
          tenantAPIProbe('owner-create-encrypted-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 201 }),
          { name: 'blocked-journal-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-journal-tenant-override-write-denied'] },
          tenantAPIProbe('owner-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 200 }),
          tenantAPIProbe('owner-list-contains-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
          tenantAPIProbe('blocked-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 404 }),
          tenantAPIProbe('blocked-list-excludes-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
          tenantAPIProbe('owner-create-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 201 }),
          { name: 'blocked-room-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-room-tenant-override-write-denied'] },
          tenantAPIProbe('owner-active-rooms-contains-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
          tenantAPIProbe('blocked-active-rooms-excludes-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
          tenantAPIProbe('owner-room-state', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 200 }),
          tenantAPIProbe('blocked-room-state-denied', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 403 }),
          {
            name: 'database-rls-context-proof',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/data/rls-db-proof.txt',
            status_code: 200,
            application_role: 'scriptureforge_app',
            row_security: 'on',
            rls_tables_verified: 9,
            rls_forced_tables: 9,
            rls_policy_scope: 'app.current_org_id',
            result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary.replace('room_participants', '')}`,
          },
        ],
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /result_summary must include verified marker room_participants/,
  );
});

test('recordEvidence rejects tenant RLS evidence without DB artifact separation marker', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'database-rls-context-proof': {
          result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary.replace('distinct_db_rls_artifact=true', '')}`,
        },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /database-rls-context-proof result_summary must include verified marker distinct_db_rls_artifact=true/,
  );
});

test('recordEvidence rejects tenant RLS evidence without explicit RLS table count markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'database-rls-context-proof': {
          result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary.replace('rls_tables_verified=9, ', '')}`,
        },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /database-rls-context-proof result_summary must include verified marker rls_tables_verified=9/,
  );
});

test('recordEvidence rejects tenant RLS evidence without structured RLS table count fields', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'database-rls-context-proof': {
          rls_tables_verified: undefined,
        },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /database-rls-context-proof must include structured rls_tables_verified=9/,
  );
});

test('recordEvidence rejects tenant RLS evidence without staging artifact marker', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        api_target: 'https://api.staging.scriptureforge.ai',
        owner_org_id: '11111111-1111-4111-8111-111111111111',
        blocked_org_id: '22222222-2222-4222-8222-222222222222',
        evidence_items: ['DATA-RLS-001'],
        probes: [
          tenantAPIProbe('owner-create-encrypted-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 201 }),
          { name: 'blocked-journal-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-journal-tenant-override-write-denied'] },
          tenantAPIProbe('owner-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 200 }),
          tenantAPIProbe('owner-list-contains-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
          tenantAPIProbe('blocked-read-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries/entry-1', status_code: 404 }),
          tenantAPIProbe('blocked-list-excludes-created-journal', { target: 'https://api.staging.scriptureforge.ai/api/v1/journal_entries', status_code: 200 }),
          tenantAPIProbe('owner-create-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 201 }),
          { name: 'blocked-room-tenant-override-write-denied', passed: true, target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/create', status_code: 400, result_summary: tenantAPIProbeMarkerSummaries['blocked-room-tenant-override-write-denied'] },
          tenantAPIProbe('owner-active-rooms-contains-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
          tenantAPIProbe('blocked-active-rooms-excludes-created-room', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/active', status_code: 200 }),
          tenantAPIProbe('owner-room-state', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 200 }),
          tenantAPIProbe('blocked-room-state-denied', { target: 'https://api.staging.scriptureforge.ai/api/v1/rooms/state/room-1', status_code: 403 }),
          {
            name: 'database-rls-context-proof',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/data/rls-db-proof.txt',
            status_code: 200,
            application_role: 'scriptureforge_app',
            row_security: 'on',
            rls_tables_verified: 9,
            rls_forced_tables: 9,
            rls_policy_scope: 'app.current_org_id',
            result_summary: `database RLS proof returned HTTP 200; verified markers: ${tenantRLSMarkerSummary.replace('staging artifact, ', '')}`,
          },
        ],
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /database-rls-context-proof result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects tenant RLS evidence without structured journal ID', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'owner-read-created-journal': { journal_id: '' },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /owner-read-created-journal probe must include structured journal_id/,
  );
});

test('recordEvidence rejects tenant RLS evidence with mismatched journal ID summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'owner-read-created-journal': { journal_id: 'entry-2' },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /owner-read-created-journal result_summary must include verified marker journal_id=entry-2/,
  );
});

test('recordEvidence rejects tenant RLS evidence when journal IDs differ across probes', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'blocked-read-created-journal': {
          journal_id: 'entry-2',
          result_summary: tenantAPIProbeMarkerSummaries['blocked-read-created-journal'].replace('journal_id=entry-1', 'journal_id=entry-2'),
        },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /blocked-read-created-journal journal_id must match owner-create-encrypted-journal journal_id/,
  );
});

test('recordEvidence rejects tenant RLS evidence without structured room ID', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'owner-room-state': { room_id: '' },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /owner-room-state probe must include structured room_id/,
  );
});

test('recordEvidence rejects tenant RLS evidence with mismatched room ID summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'owner-room-state': { room_id: 'room-2' },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /owner-room-state result_summary must include verified marker room_id=room-2/,
  );
});

test('recordEvidence rejects tenant RLS evidence when room IDs differ across probes', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      tenantRLSProbeReport({
        'blocked-room-state-denied': {
          room_id: 'room-2',
          result_summary: tenantAPIProbeMarkerSummaries['blocked-room-state-denied'].replace('room_id=room-1', 'room_id=room-2'),
        },
      }),
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /blocked-room-state-denied room_id must match owner-create-room room_id/,
  );
});

test('recordEvidence rejects web client evidence without browser smoke marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-WEB-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-WEB-001'],
        web_target: 'https://app.staging.scriptureforge.ai',
        web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
        web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
        probes: [
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
          {
            name: 'web-auth-browser-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, login',
          },
          ...webSmokeProbes().slice(1),
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /web-auth-browser-smoke result_summary must include verified marker register/,
  );
});

test('recordEvidence rejects web client evidence without per-smoke distinct artifact proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-WEB-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-WEB-001'],
        web_target: 'https://app.staging.scriptureforge.ai',
        web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
        web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
        probes: [
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
          {
            name: 'web-auth-browser-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
            status_code: 200,
            result_summary: webSmokeProbeMarkerSummaries['web-auth-browser-smoke'].replace(', distinct_web_artifacts=true', ''),
          },
          ...webSmokeProbes().slice(1),
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /web-auth-browser-smoke result_summary must include verified marker distinct_web_artifacts=true/,
  );
});

test('recordEvidence rejects web client smoke evidence with hardcoded production API URL', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-WEB-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-WEB-001'],
        web_target: 'https://app.staging.scriptureforge.ai',
        web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
        web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
        probes: [
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
          {
            name: 'web-auth-browser-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
            status_code: 200,
            user_id: 'user-staging',
            organization_id: 'org-staging',
            result_summary: `${webSmokeProbeMarkerSummaries['web-auth-browser-smoke']} release_candidate=abc123 service_version=scriptureforge-web:abc123 NEXT_PUBLIC_API_BASE_URL=https://api.scriptureforge.com`,
          },
          ...webSmokeProbes().slice(1),
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /web-auth-browser-smoke result_summary must not include forbidden marker https:\/\/api\.scriptureforge\.com/,
  );
});

test('recordEvidence rejects web client evidence without structured browser smoke resource IDs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-WEB-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-WEB-001'],
        web_target: 'https://app.staging.scriptureforge.ai',
        web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
        web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
        probes: [
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
          ...webSmokeProbes('', '', {
            'web-journal-browser-smoke': { journal_id: '' },
          }),
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /web-journal-browser-smoke probe must include structured journal_id/,
  );
});

test('recordEvidence rejects web client evidence with mismatched browser smoke user binding', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-WEB-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-WEB-001'],
        web_target: 'https://app.staging.scriptureforge.ai',
        web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
        web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
        probes: [
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
          ...webSmokeProbes('', '', {
            'web-room-browser-smoke': {
              user_id: 'user-other',
              result_summary: webSmokeProbeMarkerSummaries['web-room-browser-smoke'].replace('user_id=user-staging', 'user_id=user-other'),
            },
          }),
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /web-room-browser-smoke user_id must match web-auth-browser-smoke/,
  );
});

test('recordEvidence records production-grade mobile evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [{ id: 'CLIENT-MOBILE-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-mobile:abc123',
      evidence_items: ['CLIENT-MOBILE-001'],
      probes: [
        mobileEASProbe(),
        {
          name: 'mobile-native-crypto-smoke',
          passed: true,
          target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
          status_code: 200,
          result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'],
        },
        mobileConfigProbe(),
      ],
    },
    'artifacts/mobileprobe.json',
    'go run ./tools/mobileprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects mobile evidence without staging artifact provenance', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe({ result_summary: mobileProbeMarkerSummaries['mobile-eas-or-device-run'].replace('staging artifact, ', '') }),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'],
          },
          mobileConfigProbe(),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-eas-or-device-run result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects mobile evidence without native HTTPS artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe(),
          { name: 'mobile-native-crypto-smoke', passed: true, target: 'http://localhost/native-crypto.txt', status_code: 200, result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'] },
          mobileConfigProbe(),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-native-crypto-smoke target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence rejects mobile evidence without distinct artifact proof', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe({ result_summary: mobileProbeMarkerSummaries['mobile-eas-or-device-run'].replaceAll(', distinct_mobile_artifacts=true', '') }),
          { name: 'mobile-native-crypto-smoke', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt', status_code: 200, result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'].replaceAll(', distinct_mobile_artifacts=true', '') },
          mobileConfigProbe({ result_summary: mobileProbeMarkerSummaries['mobile-staging-config'].replaceAll(', distinct_mobile_artifacts=true', '') }),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-eas-or-device-run result_summary must include verified marker distinct_mobile_artifacts=true/,
  );
});

test('recordEvidence rejects mobile evidence with canonical duplicate artifact targets', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe({ target: 'https://ARTIFACTS.staging.scriptureforge.ai:443/mobile/shared-proof.txt?b=2&a=1' }),
          { name: 'mobile-native-crypto-smoke', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/mobile/shared-proof.txt?a=1&b=2#crypto', status_code: 200, result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'] },
          mobileConfigProbe(),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /CLIENT-MOBILE-001 mobile-native-crypto-smoke must be a distinct artifact URL from mobile-eas-or-device-run/,
  );
});

test('recordEvidence rejects mobile native crypto evidence without exact provider markers', () => {
  for (const [marker, expected] of [
    ['provider=react-native-quick-crypto', /mobile-native-crypto-smoke result_summary must include verified marker provider=react-native-quick-crypto/],
    ['native_required=true', /mobile-native-crypto-smoke result_summary must include verified marker native_required=true/],
  ]) {
    assert.throws(
      () => recordEvidence(
        { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
        {
          observed_at: '2026-06-25T12:00:00Z',
          threshold_pass: true,
          release_candidate: 'abc123',
          service_version: 'scriptureforge-mobile:abc123',
          evidence_items: ['CLIENT-MOBILE-001'],
          probes: [
            mobileEASProbe(),
            { name: 'mobile-native-crypto-smoke', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt', status_code: 200, result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'].replace(`, ${marker}`, '') },
            mobileConfigProbe(),
          ],
        },
        'artifacts/mobileprobe.json',
        'go run ./tools/mobileprobe',
      ),
      expected,
    );
  }
});

test('recordEvidence rejects mobile evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe(),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, runJournalCryptoSelfTest, react-native-quick-crypto, native provider, native module loaded, provider status react-native-quick-crypto, provider=react-native-quick-crypto, native-required true, native_required=true, AES-GCM, round-trip, unique_iv=true, unique IV, tamper rejected, associated data, wrong associated data rejected, non-extractable, provider-bound key, fallback-derived key rejected, key disposed, disposed handle rejected, passphrase wiped, plaintext cleared',
          },
          mobileConfigProbe(),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-native-crypto-smoke result_summary must include verified marker associated_data_salt_id=/,
  );
});

test('recordEvidence rejects mobile native crypto evidence without concrete associated-data salt values', () => {
  for (const [summary, expected] of [
    [
      mobileProbeMarkerSummaries['mobile-native-crypto-smoke']
        .replace('associated_data_salt_id=journal:self-test:server-derived-salt', 'associated_data_salt_id='),
      /mobile-native-crypto-smoke probe must include structured associated_data_salt_id/,
    ],
    [
      mobileProbeMarkerSummaries['mobile-native-crypto-smoke']
        .replace('associated_data_salt_version=1', 'associated_data_salt_version=0'),
      /mobile-native-crypto-smoke probe must include positive structured associated_data_salt_version/,
    ],
  ]) {
    assert.throws(
      () => recordEvidence(
        { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
        {
          observed_at: '2026-06-25T12:00:00Z',
          threshold_pass: true,
          release_candidate: 'abc123',
          service_version: 'scriptureforge-mobile:abc123',
          evidence_items: ['CLIENT-MOBILE-001'],
          probes: [
            mobileEASProbe(),
            {
              name: 'mobile-native-crypto-smoke',
              passed: true,
              target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
              status_code: 200,
              result_summary: summary,
            },
            mobileConfigProbe(),
          ],
        },
        'artifacts/mobileprobe.json',
        'go run ./tools/mobileprobe',
      ),
      expected,
    );
  }
});

test('recordEvidence rejects mobile evidence without installed staging app proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe({
            result_summary: 'got HTTP 200; verified markers: staging artifact, eas, build, finished, android, ios, native device, release channel staging, expo profile staging, platforms=android,ios, release_channel=staging, expo_profile=staging, release_candidate=abc123, service_version=scriptureforge-mobile:abc123, distinct_mobile_artifacts=true',
          }),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'],
          },
          mobileConfigProbe(),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-eas-or-device-run result_summary must include verified marker installed app/,
  );
});

test('recordEvidence rejects mobile evidence without staging deployment environment proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe(),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'],
          },
          mobileConfigProbe({
            result_summary: 'got HTTP 200; verified markers: staging artifact, EXPO_PUBLIC_API_BASE_URL, EXPO_PUBLIC_WS_BASE_URL, EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true, https://, wss://, staging, EXPO_PUBLIC_API_BASE_URL=https://api.staging.scriptureforge.ai, EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.scriptureforge.ai, release_candidate=abc123, service_version=scriptureforge-mobile:abc123, distinct_mobile_artifacts=true',
          }),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-staging-config result_summary must include verified marker EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging/,
  );
});

test('recordEvidence rejects mobile evidence with emulator or debug-client proof markers', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe({ result_summary: `${mobileProbeMarkerSummaries['mobile-eas-or-device-run']}, Android emulator` }),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'],
          },
          mobileConfigProbe(),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-eas-or-device-run result_summary must not include forbidden marker emulator/,
  );
});

test('recordEvidence rejects mobile native crypto shim and JavaScript fallback markers', () => {
  for (const [forbiddenMarker, expectedMarker] of [
    ['via Node crypto', 'node crypto'],
    ['through JavaScript fallback', 'javascript fallback'],
    ['provider=webcrypto-fallback', 'provider=webcrypto-fallback'],
    ['native_required=false', 'native_required=false'],
  ]) {
    assert.throws(
      () => recordEvidence(
        { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
        {
          observed_at: '2026-06-25T12:00:00Z',
          threshold_pass: true,
          release_candidate: 'abc123',
          service_version: 'scriptureforge-mobile:abc123',
          evidence_items: ['CLIENT-MOBILE-001'],
          probes: [
            mobileEASProbe(),
            {
              name: 'mobile-native-crypto-smoke',
              passed: true,
              target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
              status_code: 200,
              result_summary: `${mobileProbeMarkerSummaries['mobile-native-crypto-smoke']}, ${forbiddenMarker}`,
            },
            mobileConfigProbe(),
          ],
        },
        'artifacts/mobileprobe.json',
        'go run ./tools/mobileprobe',
      ),
      new RegExp(`mobile-native-crypto-smoke result_summary must not include forbidden marker ${expectedMarker}`),
    );
  }
});

test('recordEvidence rejects mobile staging config with contradictory native crypto markers', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe(),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'],
          },
          mobileConfigProbe({ result_summary: `${mobileProbeMarkerSummaries['mobile-staging-config']}, EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = false` }),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-staging-config result_summary must not include forbidden marker EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = false/,
  );
});

test('recordEvidence rejects mobile staging config with hardcoded production API URL', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:abc123',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe(),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'],
          },
          mobileConfigProbe({ result_summary: `${mobileProbeMarkerSummaries['mobile-staging-config']}, EXPO_PUBLIC_API_BASE_URL=https://api.scriptureforge.com` }),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-staging-config result_summary must not include forbidden marker https:\/\/api\.scriptureforge\.com/,
  );
});

test('recordEvidence rejects mobile evidence for a different release candidate', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-mobile:def456',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe({
            result_summary: mobileProbeMarkerSummaries['mobile-eas-or-device-run']
              .replaceAll('release_candidate=abc123', 'release_candidate=def456')
              .replaceAll('service_version=scriptureforge-mobile:abc123', 'service_version=scriptureforge-mobile:def456'),
          }),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke']
              .replaceAll('release_candidate=abc123', 'release_candidate=def456')
              .replaceAll('service_version=scriptureforge-mobile:abc123', 'service_version=scriptureforge-mobile:def456'),
          },
          mobileConfigProbe({
            result_summary: mobileProbeMarkerSummaries['mobile-staging-config']
              .replaceAll('release_candidate=abc123', 'release_candidate=def456')
              .replaceAll('service_version=scriptureforge-mobile:abc123', 'service_version=scriptureforge-mobile:def456'),
          }),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /CLIENT-MOBILE-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects probe reports whose service_version is not release-bound', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-mobile:oldsha',
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          mobileEASProbe({ result_summary: mobileProbeMarkerSummaries['mobile-eas-or-device-run'].replaceAll('service_version=scriptureforge-mobile:abc123', 'service_version=scriptureforge-mobile:oldsha') }),
          {
            name: 'mobile-native-crypto-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/mobile/native-crypto-smoke.txt',
            status_code: 200,
            result_summary: mobileProbeMarkerSummaries['mobile-native-crypto-smoke'].replaceAll('service_version=scriptureforge-mobile:abc123', 'service_version=scriptureforge-mobile:oldsha'),
          },
          mobileConfigProbe({ result_summary: mobileProbeMarkerSummaries['mobile-staging-config'].replaceAll('service_version=scriptureforge-mobile:abc123', 'service_version=scriptureforge-mobile:oldsha') }),
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /CLIENT-MOBILE-001 report service_version must include manifest release_candidate/,
  );
});

test('recordEvidence records production-grade Rust gRPC evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [{ id: 'RUST-GRPC-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-rust-engine:abc123',
      deployment_environment: 'staging',
      grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
      metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
      api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
      evidence_items: ['RUST-GRPC-001'],
      probes: [
        {
          name: 'rust-grpc-health',
          passed: true,
          target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
          status: 'SERVING',
          result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
        },
        {
          name: 'rust-metrics',
          passed: true,
          target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
          status_code: 200,
          embedding_requests: 1,
          vector_search_requests: 1,
          result_summary: rustProbeMarkerSummaries['rust-metrics'],
        },
        {
          name: 'api-rust-integration-metrics',
          passed: true,
          target: 'https://api.staging.scriptureforge.ai/metrics',
          status_code: 200,
          api_rust_vector_search_ops: 1,
          api_rust_vector_search_seconds: 0.042,
          result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
        },
      ],
    },
    'artifacts/rustprobe.json',
    'go run ./tools/rustprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects Rust gRPC evidence without structured positive metric samples', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'RUST-GRPC-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          rustProbe('rust-grpc-health', { target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051' }),
          rustProbe('rust-metrics', { target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics', embedding_requests: 0 }),
          rustProbe('api-rust-integration-metrics', { target: 'https://api.staging.scriptureforge.ai/metrics' }),
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /rust-metrics must include positive structured embedding_requests/,
  );
});

test('recordEvidence rejects Rust gRPC evidence for a different release candidate', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'RUST-GRPC-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-rust-engine:def456',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health']
              .replaceAll('release_candidate=abc123', 'release_candidate=def456')
              .replaceAll('service_version=scriptureforge-rust-engine:abc123', 'service_version=scriptureforge-rust-engine:def456'),
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics']
              .replaceAll('release_candidate=abc123', 'release_candidate=def456')
              .replaceAll('service_version=scriptureforge-rust-engine:abc123', 'service_version=scriptureforge-rust-engine:def456'),
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics']
              .replaceAll('release_candidate=abc123', 'release_candidate=def456')
              .replaceAll('service_version=scriptureforge-rust-engine:abc123', 'service_version=scriptureforge-rust-engine:def456'),
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /RUST-GRPC-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without deployment environment', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics'],
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /RUST-GRPC-001 report must include deployment_environment/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: 'metrics HTTP 200 in 12ms; verified markers: staging artifact, Prometheus metrics',
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /rust-metrics result_summary must include verified marker scriptureforge_rust_engine_/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without concrete metrics sample proof markers', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics'].replace(', rust_metrics_samples_verified=true', ''),
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /rust-metrics result_summary must include verified marker rust_metrics_samples_verified=true/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without positive Rust request sample markers', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics']
              .replace(', rust_embedding_requests_positive=true', '')
              .replace(', rust_vector_search_requests_positive=true', ''),
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /rust-metrics result_summary must include verified marker rust_embedding_requests_positive=true/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without staging artifact provenance', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics'].replace('staging artifact, ', ''),
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /rust-metrics result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without metrics proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: '127.0.0.1:50051',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: '127.0.0.1:50051',
            status: 'SERVING',
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /grpc_target must not be local\/self-test/,
  );
});

test('recordEvidence rejects Rust gRPC evidence with private-network target', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: '10.0.0.15:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: '10.0.0.15:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics'],
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /grpc_target must not be local\/self-test/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without API integration metrics proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /RUST-GRPC-001 report must include HTTPS api_metrics_target/,
  );
});

test('recordEvidence rejects Rust gRPC evidence with duplicate metrics targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'https://metrics.staging.scriptureforge.ai/rust-and-api',
        api_metrics_target: 'https://metrics.staging.scriptureforge.ai/rust-and-api',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'https://metrics.staging.scriptureforge.ai/rust-and-api',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics'],
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://metrics.staging.scriptureforge.ai/rust-and-api',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /metrics_target and api_metrics_target must be distinct/,
  );
});

test('recordEvidence rejects Rust gRPC evidence with canonical duplicate metrics targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'https://METRICS.staging.scriptureforge.ai:443/rust?b=2&a=1',
        api_metrics_target: 'https://metrics.staging.scriptureforge.ai/rust?a=1&b=2#api',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'https://METRICS.staging.scriptureforge.ai:443/rust?b=2&a=1',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['rust-metrics'],
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://metrics.staging.scriptureforge.ai/rust?a=1&b=2#api',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /RUST-GRPC-001 api_metrics_target must be a distinct artifact URL from metrics_target/,
  );
});

test('recordEvidence rejects Rust gRPC evidence without failure-counter metrics', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-rust-engine:abc123',
        deployment_environment: 'staging',
        grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
        metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
        api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
        evidence_items: ['RUST-GRPC-001'],
        probes: [
          {
            name: 'rust-grpc-health',
            passed: true,
            target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
            status: 'SERVING',
            result_summary: rustProbeMarkerSummaries['rust-grpc-health'],
          },
          {
            name: 'rust-metrics',
            passed: true,
            target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
            status_code: 200,
            result_summary: 'metrics HTTP 200 in 12ms; verified markers: staging artifact, scriptureforge_rust_engine_embedding_requests_total, scriptureforge_rust_engine_vector_search_requests_total, Prometheus metrics',
          },
          {
            name: 'api-rust-integration-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: rustProbeMarkerSummaries['api-rust-integration-metrics'],
          },
        ],
      },
      'artifacts/rustprobe.json',
      'go run ./tools/rustprobe',
    ),
    /rust-metrics result_summary must include verified marker scriptureforge_rust_engine_embedding_failures_total/,
  );
});

test('recordEvidence records production-grade Zoom evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [{ id: 'EXT-ZOOM-001', status: 'pending_external' }],
  };

  const probeNames = [
    'zoom-oauth-readiness',
    'zoom-meeting-create-or-fallback',
    'zoom-timeout-circuit-fallback',
    'zoom-webhook-signature-delivery',
    'zoom-webhook-url-validation',
    'zoom-duplicate-webhook-idempotency',
    'zoom-meeting-room-mapping',
  ];

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      evidence_items: ['EXT-ZOOM-001'],
      probes: zoomProbeReportProbes(probeNames),
    },
    'artifacts/zoomprobe.json',
    'go run ./tools/zoomprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects Zoom resilience evidence without structured fallback proof', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'EXT-ZOOM-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-timeout-circuit-fallback'
            ? { provider_timeout: undefined }
            : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-timeout-circuit-fallback probe must include structured provider_timeout=true/,
  );
});

test('recordEvidence rejects Zoom evidence for a different release candidate', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'EXT-ZOOM-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: zoomProbeMarkerSummaries[name]
            .replaceAll('release_candidate=abc123', 'release_candidate=def456')
            .replaceAll('service_version=scriptureforge-api:abc123', 'service_version=scriptureforge-api:def456'),
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /EXT-ZOOM-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects Zoom evidence without HTTPS artifact proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: [
          { name: 'zoom-oauth-readiness', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/zoom/oauth.txt', status_code: 200, result_summary: zoomProbeMarkerSummaries['zoom-oauth-readiness'] },
          { name: 'zoom-meeting-create-or-fallback', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/zoom/meeting.txt', status_code: 200, result_summary: zoomProbeMarkerSummaries['zoom-meeting-create-or-fallback'] },
          { name: 'zoom-timeout-circuit-fallback', passed: true, target: 'http://localhost/zoom/resilience.txt', status_code: 200, result_summary: zoomProbeMarkerSummaries['zoom-timeout-circuit-fallback'] },
          { name: 'zoom-webhook-signature-delivery', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/zoom/webhook.txt', status_code: 200, result_summary: zoomProbeMarkerSummaries['zoom-webhook-signature-delivery'] },
          { name: 'zoom-webhook-url-validation', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/zoom/url-validation.txt', status_code: 200, plain_token: 'zoom-plain-123', encrypted_token: 'zoom-encrypted-456', validation_response: '200', result_summary: zoomProbeMarkerSummaries['zoom-webhook-url-validation'] },
          { name: 'zoom-duplicate-webhook-idempotency', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/zoom/duplicate.txt', status_code: 200, delivery_id: 'zm-delivery-123', result_summary: zoomProbeMarkerSummaries['zoom-duplicate-webhook-idempotency'] },
          { name: 'zoom-meeting-room-mapping', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/zoom/mapping.txt', status_code: 200, result_summary: zoomProbeMarkerSummaries['zoom-meeting-room-mapping'] },
        ],
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-timeout-circuit-fallback target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence rejects Zoom evidence with duplicate artifact URLs', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          target: name === 'zoom-meeting-room-mapping'
            ? 'https://artifacts.staging.scriptureforge.ai/zoom/zoom-webhook-signature-delivery.txt'
            : `https://artifacts.staging.scriptureforge.ai/zoom/${name}.txt`,
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /EXT-ZOOM-001 zoom-meeting-room-mapping target must be a distinct artifact URL from zoom-webhook-signature-delivery target/,
  );
});

test('recordEvidence rejects Zoom evidence with canonical duplicate artifact URLs', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          target: name === 'zoom-meeting-room-mapping'
            ? 'https://ARTIFACTS.staging.scriptureforge.ai:443/zoom/zoom-webhook-signature-delivery.txt?b=2&a=1'
            : name === 'zoom-webhook-signature-delivery'
              ? 'https://artifacts.staging.scriptureforge.ai/zoom/zoom-webhook-signature-delivery.txt?a=1&b=2'
              : `https://artifacts.staging.scriptureforge.ai/zoom/${name}.txt`,
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /EXT-ZOOM-001 zoom-meeting-room-mapping target must be a distinct artifact URL from zoom-webhook-signature-delivery target/,
  );
});

test('recordEvidence rejects Zoom evidence without verified marker summaries', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'zoom-webhook-url-validation'
            ? 'got HTTP 200; staging artifact; verified markers: endpoint.url_validation, plain_token=zoom-plain-123, validation_response=200'
            : zoomProbeMarkerSummaries[name],
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-url-validation result_summary must include verified marker encrypted_token=/,
  );
});

test('recordEvidence rejects Zoom evidence without staging artifact marker', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: zoomProbeMarkerSummaries[name].replace('staging artifact; ', ''),
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-oauth-readiness result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects Zoom evidence without signature header markers', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'zoom-webhook-signature-delivery'
            ? 'got HTTP 200; staging artifact; verified markers: webhook, signature, invalid, 401, signed, 200'
            : zoomProbeMarkerSummaries[name],
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-signature-delivery result_summary must include verified marker x-zm-signature=/,
  );
});

test('recordEvidence rejects Zoom evidence without structured webhook signature fields', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-webhook-signature-delivery'
            ? { webhook_signature: '', webhook_timestamp: '' }
            : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-signature-delivery probe must include structured webhook_signature/,
  );
});

test('recordEvidence rejects Zoom evidence when webhook signature field does not match summary', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-webhook-signature-delivery'
            ? { webhook_signature: 'v0=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
            : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-signature-delivery result_summary must include verified marker x-zm-signature=v0=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/,
  );
});

test('recordEvidence rejects Zoom URL validation without structured token fields', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-webhook-url-validation'
            ? { plain_token: '', encrypted_token: '', validation_response: '' }
            : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-url-validation probe must include structured plain_token/,
  );
});

test('recordEvidence rejects Zoom URL validation when token fields do not match summary', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-webhook-url-validation'
            ? { plain_token: 'zoom-plain-999' }
            : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-url-validation result_summary must include verified marker plain_token=zoom-plain-999/,
  );
});

test('recordEvidence rejects Zoom evidence without stale replay denial markers', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'zoom-webhook-signature-delivery'
            ? zoomProbeMarkerSummaries[name].replace('stale, replay, ', '')
            : zoomProbeMarkerSummaries[name],
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-signature-delivery result_summary must include verified marker stale/,
  );
});

test('recordEvidence rejects Zoom evidence with disabled signature verification marker', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'zoom-webhook-signature-delivery'
            ? `${zoomProbeMarkerSummaries[name]}, signature verification disabled`
            : zoomProbeMarkerSummaries[name],
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-webhook-signature-delivery result_summary must not include forbidden marker signature verification disabled/,
  );
});

test('recordEvidence rejects Zoom duplicate evidence without structured delivery ID', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          delivery_id: name === 'zoom-duplicate-webhook-idempotency' ? undefined : undefined,
          result_summary: name === 'zoom-duplicate-webhook-idempotency'
            ? zoomProbeMarkerSummaries[name].replace('delivery_id=zm-delivery-123, ', '')
            : zoomProbeMarkerSummaries[name],
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-duplicate-webhook-idempotency result_summary must include verified marker delivery_id=/,
  );
});

test('recordEvidence rejects Zoom duplicate evidence without report delivery_id field', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-duplicate-webhook-idempotency' ? { delivery_id: '' } : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-duplicate-webhook-idempotency probe must include structured delivery_id/,
  );
});

test('recordEvidence rejects Zoom duplicate evidence when delivery_id field does not match summary', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-duplicate-webhook-idempotency' ? { delivery_id: 'zm-delivery-999' } : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-duplicate-webhook-idempotency result_summary must include verified marker delivery_id=zm-delivery-999/,
  );
});

test('recordEvidence rejects Zoom duplicate evidence without tracking header proof', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'zoom-duplicate-webhook-idempotency'
            ? zoomProbeMarkerSummaries[name].replace('x-zm-trackingid, ', '')
            : zoomProbeMarkerSummaries[name],
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-duplicate-webhook-idempotency result_summary must include verified marker x-zm-trackingid/,
  );
});

test('recordEvidence rejects Zoom evidence without internal room mapping safeguards', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'zoom-meeting-room-mapping'
            ? 'got HTTP 200; staging artifact; verified markers: meeting_external_id, live_rooms, room, mapped'
            : zoomProbeMarkerSummaries[name],
        })),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-meeting-room-mapping result_summary must include verified marker meeting_external_id=/,
  );
});

test('recordEvidence rejects Zoom room mapping without structured meeting ID', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-meeting-room-mapping' ? { meeting_external_id: '' } : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-meeting-room-mapping probe must include structured meeting_external_id/,
  );
});

test('recordEvidence rejects Zoom room mapping when structured IDs do not match summary', () => {
  const probeNames = Object.keys(zoomProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-ZOOM-001'],
        probes: zoomProbeReportProbes(probeNames, (name) => (
          name === 'zoom-meeting-room-mapping' ? { internal_room_id: 'room-other' } : {}
        )),
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-meeting-room-mapping result_summary must include verified marker internal_room_id=room-other/,
  );
});

test('recordEvidence records production-grade AI evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [{ id: 'EXT-AI-001', status: 'pending_external' }],
  };

  const probeNames = [
    'ai-provider-config',
    'ai-generation-route',
    'ai-timeout-degradation',
    'ai-citation-verification',
    'ai-audit-persistence',
  ];

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      evidence_items: ['EXT-AI-001'],
      probes: aiProbeReportProbes(probeNames),
    },
    'artifacts/aiprobe.json',
    'go run ./tools/aiprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects AI provider evidence without structured config values', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'EXT-AI-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-provider-config'
            ? { ai_provider: undefined }
            : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-provider-config probe must include structured ai_provider/,
  );
});

test('recordEvidence rejects AI evidence for a different release candidate', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'EXT-AI-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          result_summary: aiProbeMarkerSummaries[name]
            .replaceAll('release_candidate=abc123', 'release_candidate=def456')
            .replaceAll('service_version=scriptureforge-api:abc123', 'service_version=scriptureforge-api:def456'),
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /EXT-AI-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects AI evidence without HTTPS artifact proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['EXT-AI-001'],
        probes: [
          { name: 'ai-provider-config', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/ai/provider.txt', status_code: 200, ai_provider: 'openai', ai_chat_model: 'gpt-staging', ai_chat_endpoint: 'https://api.openai.com/v1/chat/completions', ai_http_timeout_ms: '3500', ai_max_retries: '1', result_summary: aiProbeMarkerSummaries['ai-provider-config'] },
          { name: 'ai-generation-route', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/ai/generation.txt', status_code: 200, request_id: 'req-123', organization_id: 'org-123', user_id: 'user-123', result_summary: aiProbeMarkerSummaries['ai-generation-route'] },
          { name: 'ai-timeout-degradation', passed: true, target: 'http://localhost/ai/degradation.txt', status_code: 200, provider_timeout: true, retry_exhausted: true, fail_closed: true, result_summary: aiProbeMarkerSummaries['ai-timeout-degradation'] },
          { name: 'ai-citation-verification', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/ai/citation.txt', status_code: 200, citation_id: 'cite-123', result_summary: aiProbeMarkerSummaries['ai-citation-verification'] },
          aiProbeReportProbe('ai-audit-persistence', { target: 'https://artifacts.staging.scriptureforge.ai/ai/audit.txt' }),
        ],
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-timeout-degradation target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence rejects AI evidence with duplicate artifact URLs', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          target: name === 'ai-audit-persistence'
            ? 'https://artifacts.staging.scriptureforge.ai/ai/ai-citation-verification.txt'
            : `https://artifacts.staging.scriptureforge.ai/ai/${name}.txt`,
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /EXT-AI-001 ai-audit-persistence target must be a distinct artifact URL from ai-citation-verification target/,
  );
});

test('recordEvidence rejects AI evidence without verified marker summaries', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'ai-audit-persistence'
            ? 'got HTTP 200; staging artifact; verified markers: ai_request_logs, organization_id=org-123, user_id=user-123, request_id=req-123, succeeded, failed, verified'
            : aiProbeMarkerSummaries[name],
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence result_summary must include verified marker citation_trails/,
  );
});

test('recordEvidence rejects AI evidence with disabled citation or audit markers', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'ai-citation-verification'
            ? `${aiProbeMarkerSummaries[name]}, citation verification disabled`
            : aiProbeMarkerSummaries[name],
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-citation-verification result_summary must not include forbidden marker citation verification disabled/,
  );
});

test('recordEvidence rejects AI evidence without provider redaction proof', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'ai-provider-config'
            ? 'got HTTP 200; staging artifact; verified markers: AI_PROVIDER, AI_CHAT_MODEL, AI_CHAT_ENDPOINT, AI_HTTP_TIMEOUT_MS, AI_MAX_RETRIES, configured'
            : aiProbeMarkerSummaries[name],
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-provider-config result_summary must include verified marker OPENAI_API_KEY redacted/,
  );
});

test('recordEvidence rejects AI evidence without JWT claim generation proof', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'ai-generation-route'
            ? 'got HTTP 200; staging artifact; verified markers: /api/v1/ai/generate/study, authenticated, tenant, 200, generated_curriculum, [Genesis 1:1]'
            : aiProbeMarkerSummaries[name],
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-generation-route result_summary must include verified marker JWT claims/,
  );
});

test('recordEvidence rejects AI evidence without tenant RLS audit proof', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'ai-audit-persistence'
            ? 'got HTTP 200; staging artifact; verified markers: ai_request_logs, citation_trails, organization_id=org-123, user_id=user-123, request_id=req-123, citation_id=cite-123, succeeded, failed, verified'
            : aiProbeMarkerSummaries[name],
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence result_summary must include verified marker tenant rls/,
  );
});

test('recordEvidence rejects AI evidence without staging artifact marker', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => ({
          result_summary: aiProbeMarkerSummaries[name].replace('staging artifact; ', ''),
        })),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-provider-config result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects AI audit evidence without structured request ID', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-audit-persistence' ? { request_id: '' } : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence probe must include structured request_id/,
  );
});

test('recordEvidence rejects AI audit evidence when request ID field does not match summary', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-audit-persistence' ? { request_id: 'req-999' } : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence result_summary must include verified marker request_id=req-999/,
  );
});

test('recordEvidence rejects AI generation evidence without structured request ID', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-generation-route' ? { request_id: '' } : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-generation-route probe must include structured request_id/,
  );
});

test('recordEvidence rejects AI audit evidence when request ID differs from generation', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-audit-persistence'
            ? {
                request_id: 'req-other',
                result_summary: aiProbeMarkerSummaries[name].replace('request_id=req-123', 'request_id=req-other'),
              }
            : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence request_id must match ai-generation-route request_id/,
  );
});

test('recordEvidence rejects AI audit evidence when organization ID differs from generation', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-audit-persistence'
            ? {
                organization_id: 'org-other',
                result_summary: aiProbeMarkerSummaries[name].replace('organization_id=org-123', 'organization_id=org-other'),
              }
            : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence organization_id must match ai-generation-route organization_id/,
  );
});

test('recordEvidence rejects AI audit evidence when user ID differs from generation', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-audit-persistence'
            ? {
                user_id: 'user-other',
                result_summary: aiProbeMarkerSummaries[name].replace('user_id=user-123', 'user_id=user-other'),
              }
            : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence user_id must match ai-generation-route user_id/,
  );
});

test('recordEvidence rejects AI citation evidence without structured citation ID', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-citation-verification' ? { citation_id: '' } : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-citation-verification probe must include structured citation_id/,
  );
});

test('recordEvidence rejects AI audit evidence when citation ID differs from citation verification', () => {
  const probeNames = Object.keys(aiProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-AI-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['EXT-AI-001'],
        probes: aiProbeReportProbes(probeNames, (name) => (
          name === 'ai-audit-persistence'
            ? {
                citation_id: 'cite-other',
                result_summary: aiProbeMarkerSummaries[name].replace('citation_id=cite-123', 'citation_id=cite-other'),
              }
            : {}
        )),
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-audit-persistence citation_id must match ai-citation-verification citation_id/,
  );
});

test('recordEvidence rejects TLS evidence without DNS and ACM artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-web:abc123',
        evidence_items: ['DEPLOY-TLS-001'],
        probes: [{ name: 'api-tls', passed: true }],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /must include HTTPS dns_artifact_url/,
  );
});

test('recordEvidence records production-grade TLS and web reachability evidence', () => {
  const manifest = {
    items: [
      { id: 'DEPLOY-TLS-001', status: 'pending_external' },
      { id: 'CLIENT-WEB-001', status: 'pending_external' },
    ],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-web:abc123',
      evidence_items: ['DEPLOY-TLS-001', 'CLIENT-WEB-001'],
      api_target: 'https://api.staging.scriptureforge.ai',
      web_target: 'https://app.staging.scriptureforge.ai',
      dns_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/dns.txt',
      acm_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/acm.txt',
      web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
      web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
      web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
      probes: [
        { name: 'api-live', passed: true, target: 'https://api.staging.scriptureforge.ai/live', status_code: 200, result_summary: stagingProbeMarkerSummaries['api-live'] },
        { name: 'api-ready', passed: true, target: 'https://api.staging.scriptureforge.ai/ready', status_code: 200, result_summary: stagingProbeMarkerSummaries['api-ready'] },
        { name: 'api-tls', passed: true, target: 'https://api.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['api-tls'] },
        { name: 'api-http-redirect', passed: true, target: 'http://api.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://api.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['api-http-redirect'] },
        { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
        { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
        { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
        ...webSmokeProbes('abc123', 'scriptureforge-web:abc123'),
      ],
    },
    'artifacts/stagingprobe.json',
    'go run ./tools/stagingprobe -api-base=https://api.staging.scriptureforge.ai -web-base=https://app.staging.scriptureforge.ai',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
});

test('recordEvidence rejects TLS evidence with canonical duplicate DNS and ACM artifact URLs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TLS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-web:abc123',
        evidence_items: ['DEPLOY-TLS-001'],
        api_target: 'https://api.staging.scriptureforge.ai',
        dns_artifact_url: 'https://ARTIFACTS.staging.scriptureforge.ai:443/tls/shared-proof.txt?b=2&a=1',
        acm_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/shared-proof.txt?a=1&b=2#certificate',
        probes: [
          { name: 'api-live', passed: true, target: 'https://api.staging.scriptureforge.ai/live', status_code: 200, result_summary: stagingProbeMarkerSummaries['api-live'] },
          { name: 'api-ready', passed: true, target: 'https://api.staging.scriptureforge.ai/ready', status_code: 200, result_summary: stagingProbeMarkerSummaries['api-ready'] },
          { name: 'api-tls', passed: true, target: 'https://api.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['api-tls'] },
          { name: 'api-http-redirect', passed: true, target: 'http://api.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://api.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['api-http-redirect'] },
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe -api-base=https://api.staging.scriptureforge.ai',
    ),
    /DEPLOY-TLS-001 acm_artifact_url must be a distinct artifact URL from dns_artifact_url/,
  );
});

test('recordEvidence rejects TLS evidence for a different release candidate', () => {
  const staleSummaries = Object.fromEntries(
    Object.entries(stagingProbeMarkerSummaries)
      .map(([name, summary]) => [
        name,
        summary
          .replaceAll('release_candidate=abc123', 'release_candidate=def456')
          .replaceAll('service_version=scriptureforge-web:abc123', 'service_version=scriptureforge-web:def456'),
      ]),
  );

  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'DEPLOY-TLS-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-web:def456',
        evidence_items: ['DEPLOY-TLS-001'],
        api_target: 'https://api.staging.scriptureforge.ai',
        dns_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/dns.txt',
        acm_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/acm.txt',
        probes: [
          { name: 'api-live', passed: true, target: 'https://api.staging.scriptureforge.ai/live', status_code: 200, result_summary: staleSummaries['api-live'] },
          { name: 'api-ready', passed: true, target: 'https://api.staging.scriptureforge.ai/ready', status_code: 200, result_summary: staleSummaries['api-ready'] },
          { name: 'api-tls', passed: true, target: 'https://api.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: staleSummaries['api-tls'] },
          { name: 'api-http-redirect', passed: true, target: 'http://api.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://api.staging.scriptureforge.ai', result_summary: staleSummaries['api-http-redirect'] },
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe -api-base=https://api.staging.scriptureforge.ai',
    ),
    /DEPLOY-TLS-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects TLS evidence without API readiness proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TLS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-web:abc123',
        evidence_items: ['DEPLOY-TLS-001'],
        api_target: 'https://api.staging.scriptureforge.ai',
        dns_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/dns.txt',
        acm_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/acm.txt',
        probes: [
          { name: 'api-live', passed: true, target: 'https://api.staging.scriptureforge.ai/live', status_code: 200, result_summary: stagingProbeMarkerSummaries['api-live'] },
          { name: 'api-tls', passed: true, target: 'https://api.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['api-tls'] },
          { name: 'api-http-redirect', passed: true, target: 'http://api.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://api.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['api-http-redirect'] },
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe -api-base=https://api.staging.scriptureforge.ai',
    ),
    /must include api-ready probe/,
  );
});

test('recordEvidence rejects TLS and web reports without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'DEPLOY-TLS-001', status: 'pending_external' },
          { id: 'CLIENT-WEB-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-web:abc123',
        evidence_items: ['DEPLOY-TLS-001', 'CLIENT-WEB-001'],
        api_target: 'https://api.staging.scriptureforge.ai',
        web_target: 'https://app.staging.scriptureforge.ai',
        dns_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/dns.txt',
        acm_artifact_url: 'https://artifacts.staging.scriptureforge.ai/tls/acm.txt',
        web_auth_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/auth-smoke.txt',
        web_journal_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/journal-smoke.txt',
        web_room_smoke_url: 'https://artifacts.staging.scriptureforge.ai/web/room-smoke.txt',
        probes: [
          { name: 'api-live', passed: true, target: 'https://api.staging.scriptureforge.ai/live', status_code: 200, result_summary: 'got HTTP 200' },
          { name: 'api-ready', passed: true, target: 'https://api.staging.scriptureforge.ai/ready', status_code: 200, result_summary: stagingProbeMarkerSummaries['api-ready'] },
          { name: 'api-tls', passed: true, target: 'https://api.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['api-tls'] },
          { name: 'api-http-redirect', passed: true, target: 'http://api.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://api.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['api-http-redirect'] },
          { name: 'web-root', passed: true, target: 'https://app.staging.scriptureforge.ai', status_code: 200, result_summary: stagingProbeMarkerSummaries['web-root'] },
          { name: 'web-tls', passed: true, target: 'https://app.staging.scriptureforge.ai', tls_version: 'TLS1.3', cert_not_after: '2026-12-25T00:00:00Z', result_summary: stagingProbeMarkerSummaries['web-tls'] },
          { name: 'web-http-redirect', passed: true, target: 'http://app.staging.scriptureforge.ai', status_code: 301, redirect_to: 'https://app.staging.scriptureforge.ai', result_summary: stagingProbeMarkerSummaries['web-http-redirect'] },
          ...webSmokeProbes('abc123', 'scriptureforge-web:abc123'),
        ],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe -api-base=https://api.staging.scriptureforge.ai -web-base=https://app.staging.scriptureforge.ai',
    ),
    /api-live result_summary must include verified marker api-live/,
  );
});

test('recordEvidence records production-grade Terraform deployment evidence', () => {
  const manifest = {
    items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      evidence_items: ['DEPLOY-TF-001'],
      probes: [
        {
          name: 'terraform-remote-backend-init',
          passed: true,
          target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt',
          status_code: 200,
          result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'],
        },
        {
          name: 'terraform-staging-plan',
          passed: true,
          target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt',
          status_code: 200,
          result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'],
        },
        terraformApplyProbe(),
      ],
    },
    'artifacts/deploymentprobe-terraform.json',
    'go run ./tools/deploymentprobe -probe-terraform',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects deployment probe reports for a different release candidate', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /DEPLOY-TF-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects Terraform deployment evidence without remote artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'http://localhost/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-plan target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence rejects Terraform deployment evidence with duplicate artifact URLs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/shared-terraform-proof.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/shared-terraform-proof.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /DEPLOY-TF-001 terraform-staging-plan target must be a distinct artifact URL from terraform-remote-backend-init target/,
  );
});

test('recordEvidence rejects Terraform evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'].replace('aws_iam_role', '') },
          terraformApplyProbe(),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-plan result_summary must include verified marker aws_iam_role/,
  );
});

test('recordEvidence rejects Terraform evidence with admitted failure summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: `${deploymentProbeMarkerSummaries['terraform-staging-plan']}; terraform plan failed` },
          terraformApplyProbe(),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-plan result_summary must not include forbidden marker terraform plan failed/,
  );
});

test('recordEvidence rejects Terraform evidence without remote state lock and encryption markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'].replace('dynamodb_table, ', '') },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-remote-backend-init result_summary must include verified marker dynamodb_table/,
  );
});

test('recordEvidence rejects Terraform evidence without staging artifact marker', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'].replace('staging artifact; ', '') },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'].replace('staging artifact; ', '') },
          terraformApplyProbe(deploymentProbeMarkerSummaries['terraform-staging-apply-or-approval'].replace('staging artifact; ', '')),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-remote-backend-init result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects Terraform init and plan evidence without release linkage markers', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          {
            name: 'terraform-remote-backend-init',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt',
            status_code: 200,
            result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init']
              .replace(', release_candidate=abc123, service_version=scriptureforge-api:abc123', ''),
          },
          {
            name: 'terraform-staging-plan',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt',
            status_code: 200,
            result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan']
              .replace(', release_candidate=abc123, service_version=scriptureforge-api:abc123', ''),
          },
          terraformApplyProbe(),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
    ),
    /terraform-remote-backend-init result_summary must include verified marker release_candidate=/,
  );
});

test('recordEvidence rejects Terraform apply evidence without release linkage markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe('got HTTP 200; staging artifact; verified markers: Apply complete, Resources:, 0 destroyed'),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-apply-or-approval result_summary must include apply-complete or deployment-approval markers/,
  );
});

test('recordEvidence rejects Terraform apply evidence without zero-destroy proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe('got HTTP 200; staging artifact; verified markers: Apply complete, Resources:, release_candidate=abc123, service_version=scriptureforge-api:abc123, distinct_terraform_artifacts=true'),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-apply-or-approval result_summary must include apply-complete or deployment-approval markers/,
  );
});

test('recordEvidence rejects Terraform approval evidence without change ticket marker', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(deploymentProbeMarkerSummaries['terraform-staging-apply-or-approval'].replace('change_ticket=PLATFORM-123, ', '')),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-apply-or-approval result_summary must include apply-complete or deployment-approval markers/,
  );
});

test('recordEvidence rejects Terraform approval evidence without change ticket ID', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(deploymentProbeMarkerSummaries['terraform-staging-apply-or-approval'].replace('change_ticket=PLATFORM-123', 'change_ticket=')),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-apply-or-approval deployment approval summary must include change_ticket=<ticket-id>/,
  );
});

test('recordEvidence rejects Terraform approval evidence without structured change ticket', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(deploymentProbeMarkerSummaries['terraform-staging-apply-or-approval'], { change_ticket: undefined }),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-apply-or-approval deployment approval report must include structured change_ticket/,
  );
});

test('recordEvidence rejects Terraform approval evidence with mismatched structured change ticket', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TF-001'],
        probes: [
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-init.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-remote-backend-init'] },
          { name: 'terraform-staging-plan', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/deploy/terraform-plan.txt', status_code: 200, result_summary: deploymentProbeMarkerSummaries['terraform-staging-plan'] },
          terraformApplyProbe(deploymentProbeMarkerSummaries['terraform-staging-apply-or-approval'], { change_ticket: 'PLATFORM-999' }),
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-apply-or-approval deployment approval summary must match structured change_ticket/,
  );
});

test('recordEvidence records production-grade Kubernetes deployment evidence', () => {
  const manifest = {
    items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      evidence_items: ['DEPLOY-K8S-001'],
      probes: [
        {
          name: 'kubernetes-rollout-status',
          passed: true,
          target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
          result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
        },
        {
          name: 'kubernetes-workload-resources',
          passed: true,
          target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
          result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'],
        },
      ],
    },
    'artifacts/deploymentprobe-k8s.json',
    'go run ./tools/deploymentprobe -probe-kubernetes',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects Kubernetes evidence without staging artifact marker', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'].replace('staging artifact; ', ''),
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'].replace('staging artifact; ', ''),
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-rollout-status result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects Kubernetes evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'].replace('pdb', ''),
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-workload-resources result_summary must include verified marker pdb/,
  );
});

test('recordEvidence rejects Kubernetes rollout evidence without release linkage markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status']
              .replace(', release_candidate=abc123', '')
              .replace(', service_version=scriptureforge-api:abc123', ''),
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'],
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-rollout-status result_summary must include verified marker release_candidate/,
  );
});

test('recordEvidence rejects Kubernetes evidence with duplicate rollout and resource artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-shared.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://ARTIFACTS.staging.scriptureforge.ai:443/deploy/kubectl-shared.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'],
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /DEPLOY-K8S-001 kubernetes-workload-resources must be a distinct artifact URL from kubernetes-rollout-status/,
  );
});

test('recordEvidence rejects Kubernetes evidence without distinct artifact summary marker', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'].replace(', distinct_kubernetes_artifacts=true', ''),
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-workload-resources result_summary must include verified marker distinct_kubernetes_artifacts=true/,
  );
});

test('recordEvidence rejects Kubernetes evidence without rollout safety markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'].replace('maxUnavailable=0, ', ''),
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-workload-resources result_summary must include verified marker maxUnavailable=0/,
  );
});

test('recordEvidence rejects Kubernetes evidence without image digest linkage markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources']
              .replace('scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, ', '')
              .replace('scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, ', '')
              .replace('scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc, ', ''),
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-workload-resources result_summary must include verified marker sha256:/,
  );
});

test('recordEvidence rejects Kubernetes evidence with only generic image digest markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources']
              .replace('scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'scriptureforge-api@sha256:api')
              .replace('scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'scriptureforge-web@sha256:web')
              .replace('scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 'scriptureforge-rust-engine@sha256:rust'),
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-workload-resources result_summary must include at least 3 immutable image digests, found 0/,
  );
});

test('recordEvidence rejects Kubernetes evidence with unbound immutable image digests', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-rollout-status'],
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources']
              .replace('scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, ', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, ')
              .replace('scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, ', 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, ')
              .replace('scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc, ', 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc, '),
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-workload-resources result_summary must include immutable image digest bound to scriptureforge-api/,
  );
});

test('recordEvidence rejects Kubernetes evidence with admitted rollout failure summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [
          {
            name: 'kubernetes-rollout-status',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-rollout-status.txt',
            result_summary: `${deploymentProbeMarkerSummaries['kubernetes-rollout-status']}; rollout failed`,
          },
          {
            name: 'kubernetes-workload-resources',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/deploy/kubectl-resources.txt',
            result_summary: deploymentProbeMarkerSummaries['kubernetes-workload-resources'],
          },
        ],
      },
      'artifacts/deploymentprobe-k8s.json',
      'go run ./tools/deploymentprobe -probe-kubernetes',
    ),
    /kubernetes-rollout-status result_summary must not include forbidden marker rollout failed/,
  );
});

test('recordEvidence rejects Kubernetes evidence without rollout and resource artifact probes', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [{ name: 'api-ready', passed: true, target: 'https://api.staging.scriptureforge.ai/ready' }],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /must include kubernetes-rollout-status probe/,
  );
});

test('recordEvidence records production-grade observability evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [
      { id: 'OBS-OTEL-001', status: 'pending_external' },
      { id: 'OBS-ALERT-001', status: 'pending_external' },
    ],
  };

  const probeNames = [
    'collector-otlp-config',
    'api-prometheus-metrics',
    'rust-prometheus-metrics',
    'trace-backend-search',
    'log-backend-trace-correlation',
    'dashboard-import',
    'alert-rules-loaded',
    'alert-delivery-status',
    'telemetry-retention-policy',
  ];

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      trace_id: observabilityTraceID,
      observed_route: '/api/v1/ai/generate/study',
      http_method: 'POST',
      tenant_id: 'org-staging',
      user_id: 'user-staging',
      role: 'admin',
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      alert_name: 'ScriptureForgeHighErrorRate',
      alert_receiver: 'staging-release',
      evidence_items: ['OBS-OTEL-001', 'OBS-ALERT-001'],
      probes: observabilityProbeReportProbes(probeNames),
    },
    'artifacts/observabilityprobe.json',
    'go run ./tools/observabilityprobe -probe-otel -probe-alerts',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
});

test('recordEvidence rejects observability evidence without staging artifact provenance', () => {
  const probeNames = [
    'collector-otlp-config',
    'api-prometheus-metrics',
    'rust-prometheus-metrics',
    'trace-backend-search',
    'log-backend-trace-correlation',
  ];

  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
      trace_id: observabilityTraceID,
      observed_route: '/api/v1/ai/generate/study',
      http_method: 'POST',
      tenant_id: 'org-staging',
      user_id: 'user-staging',
      role: 'admin',
      release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: probeNames.map((name) => ({
          name,
          passed: true,
          target: observabilityProbeTarget(name),
          status_code: 200,
          result_summary: name === 'api-prometheus-metrics'
            ? observabilityProbeMarkerSummaries[name].replace('staging artifact, ', '')
            : observabilityProbeMarkerSummaries[name],
        })),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /api-prometheus-metrics result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects observability log evidence without exact structured tenant principal markers', () => {
  const probeNames = [
    'collector-otlp-config',
    'api-prometheus-metrics',
    'rust-prometheus-metrics',
    'trace-backend-search',
    'log-backend-trace-correlation',
  ];

  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: observabilityProbeReportProbes(probeNames, (name) => (name === 'log-backend-trace-correlation' ? {
          result_summary: observabilityProbeMarkerSummaries[name].replace('tenant_id=org-staging', 'tenant_id=org-other'),
        } : {})),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /log-backend-trace-correlation result_summary must include verified marker tenant_id=org-staging/,
  );
});

test('recordEvidence rejects observability evidence with placeholder trace IDs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: 'trace-abc',
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['api-prometheus-metrics'] },
          { name: 'rust-prometheus-metrics', passed: true, target: 'https://rust.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          { name: 'trace-backend-search', passed: true, target: 'https://traces.staging.scriptureforge.ai/search?trace_id=trace-abc', status_code: 200, result_summary: observabilityProbeMarkerSummaries['trace-backend-search'] },
          { name: 'log-backend-trace-correlation', passed: true, target: 'https://logs.staging.scriptureforge.ai/search?trace_id=trace-abc', status_code: 200, result_summary: observabilityProbeMarkerSummaries['log-backend-trace-correlation'] },
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /OBS-OTEL-001 trace_id must be a 32-character lowercase hex OpenTelemetry trace ID/,
  );
});

test('recordEvidence rejects observability evidence for a different release candidate', () => {
  const probeNames = Object.keys(observabilityProbeMarkerSummaries);
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [
          { id: 'OBS-OTEL-001', status: 'pending_external' },
          { id: 'OBS-ALERT-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-OTEL-001', 'OBS-ALERT-001'],
        probes: observabilityProbeReportProbes(probeNames, (name) => ({
          result_summary: observabilityProbeMarkerSummaries[name]
            .replaceAll('release_candidate=abc123', 'release_candidate=def456')
            .replaceAll('service_version=scriptureforge-api:abc123', 'service_version=scriptureforge-api:def456'),
        })),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel -probe-alerts',
    ),
    /OBS-OTEL-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects observability evidence with duplicate OTEL artifact URLs', () => {
  const probeNames = [
    'collector-otlp-config',
    'api-prometheus-metrics',
    'rust-prometheus-metrics',
    'trace-backend-search',
    'log-backend-trace-correlation',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: observabilityProbeReportProbes(probeNames, (name) => ({
          target: name === 'log-backend-trace-correlation'
            ? `https://traces.staging.scriptureforge.ai/search?trace_id=${observabilityTraceID}`
            : observabilityProbeTarget(name),
        })),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /OBS-OTEL-001 log-backend-trace-correlation target must be a distinct artifact URL from trace-backend-search target/,
  );
});

test('recordEvidence rejects observability evidence with duplicate alert artifact URLs', () => {
  const probeNames = [
    'dashboard-import',
    'alert-rules-loaded',
    'alert-delivery-status',
    'telemetry-retention-policy',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-ALERT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-ALERT-001'],
        probes: observabilityProbeReportProbes(probeNames, (name) => ({
          target: name === 'telemetry-retention-policy'
            ? 'https://observability.staging.scriptureforge.ai/alert-delivery-status'
            : observabilityProbeTarget(name),
        })),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-alerts',
    ),
    /OBS-ALERT-001 telemetry-retention-policy target must be a distinct artifact URL from alert-delivery-status target/,
  );
});

test('recordEvidence rejects observability evidence without tenant-aware log markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['api-prometheus-metrics'] },
          { name: 'rust-prometheus-metrics', passed: true, target: 'https://rust.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          observabilityProbeReportProbe('trace-backend-search', { target: 'https://traces.staging.scriptureforge.ai/search?trace_id=11112222333344445555666677778888' }),
          observabilityProbeReportProbe('log-backend-trace-correlation', {
            result_summary: 'got HTTP 200; verified markers: staging artifact, 11112222333344445555666677778888, trace_id, service_version, deployment_environment, release_candidate=abc123, service_version=scriptureforge-api:abc123',
          }),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /log-backend-trace-correlation result_summary must include verified marker scriptureforge-rust-engine/,
  );
});

test('recordEvidence rejects observability evidence with mismatched trace ID summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['api-prometheus-metrics'] },
          { name: 'rust-prometheus-metrics', passed: true, target: 'https://rust.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          observabilityProbeReportProbe('trace-backend-search', {
            result_summary: observabilityProbeMarkerSummaries['trace-backend-search'].replace(observabilityTraceID, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
          }),
          observabilityProbeReportProbe('log-backend-trace-correlation'),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /trace-backend-search result_summary must include verified marker 11112222333344445555666677778888/,
  );
});

test('recordEvidence rejects observability trace evidence without structured probe binding', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: observabilityProbeReportProbes([
          'collector-otlp-config',
          'api-prometheus-metrics',
          'rust-prometheus-metrics',
          'trace-backend-search',
          'log-backend-trace-correlation',
        ], (name) => (name === 'trace-backend-search' ? { trace_id: undefined } : {})),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /trace-backend-search structured trace_id must be a 32-character lowercase hex OpenTelemetry trace ID/,
  );
});

test('recordEvidence rejects observability log evidence with mismatched structured tenant principal', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: observabilityProbeReportProbes([
          'collector-otlp-config',
          'api-prometheus-metrics',
          'rust-prometheus-metrics',
          'trace-backend-search',
          'log-backend-trace-correlation',
        ], (name) => (name === 'log-backend-trace-correlation' ? { tenant_id: 'org-other' } : {})),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /log-backend-trace-correlation structured tenant_id must match report tenant_id/,
  );
});

test('recordEvidence rejects observability evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [
          { id: 'OBS-OTEL-001', status: 'pending_external' },
          { id: 'OBS-ALERT-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-OTEL-001', 'OBS-ALERT-001'],
        probes: observabilityProbeReportProbes(Object.keys(observabilityProbeMarkerSummaries), (name) => ({
          result_summary: name === 'alert-delivery-status'
            ? 'got HTTP 200; verified markers: staging artifact, success, delivered, test alert, alertmanager, alertname=ScriptureForgeHighErrorRate, receiver=staging-release, release_candidate=abc123, service_version=scriptureforge-api:abc123'
            : observabilityProbeMarkerSummaries[name],
        })),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel -probe-alerts',
    ),
    /alert-delivery-status result_summary must include verified marker delivery_id=/,
  );
});

test('recordEvidence rejects observability alert delivery evidence without structured delivery ID', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-ALERT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-ALERT-001'],
        probes: observabilityProbeReportProbes([
          'dashboard-import',
          'alert-rules-loaded',
          'alert-delivery-status',
          'telemetry-retention-policy',
        ], (name) => (name === 'alert-delivery-status' ? { delivery_id: undefined } : {})),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-alerts',
    ),
    /OBS-ALERT-001 alert-delivery-status probe must include structured delivery_id/,
  );
});

test('recordEvidence rejects observability alert delivery evidence without structured alert identity', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-ALERT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-ALERT-001'],
        probes: observabilityProbeReportProbes([
          'dashboard-import',
          'alert-rules-loaded',
          'alert-delivery-status',
          'telemetry-retention-policy',
        ], (name) => (name === 'alert-delivery-status' ? { alert_name: undefined } : {})),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-alerts',
    ),
    /OBS-ALERT-001 alert-delivery-status probe must include structured alert_name/,
  );
});

test('recordEvidence rejects observability alert delivery evidence with mismatched structured receiver', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-ALERT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-ALERT-001'],
        probes: observabilityProbeReportProbes([
          'dashboard-import',
          'alert-rules-loaded',
          'alert-delivery-status',
          'telemetry-retention-policy',
        ], (name) => (name === 'alert-delivery-status' ? { alert_receiver: 'other-receiver' } : {})),
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-alerts',
    ),
    /OBS-ALERT-001 alert-delivery-status structured alert_receiver must match report alert_receiver/,
  );
});

test('recordEvidence rejects observability alert delivery contradiction markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-ALERT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-ALERT-001'],
        probes: [
          { name: 'dashboard-import', passed: true, target: 'https://grafana.staging.scriptureforge.ai/d/scriptureforge', status_code: 200, result_summary: observabilityProbeMarkerSummaries['dashboard-import'] },
          { name: 'alert-rules-loaded', passed: true, target: 'https://prometheus.staging.scriptureforge.ai/rules', status_code: 200, result_summary: observabilityProbeMarkerSummaries['alert-rules-loaded'] },
          observabilityProbeReportProbe('alert-delivery-status', { target: 'https://alertmanager.staging.scriptureforge.ai/status', result_summary: `${observabilityProbeMarkerSummaries['alert-delivery-status']}; alert silenced; not delivered` }),
          { name: 'telemetry-retention-policy', passed: true, target: 'https://observability.staging.scriptureforge.ai/retention', status_code: 200, result_summary: observabilityProbeMarkerSummaries['telemetry-retention-policy'] },
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-alerts',
    ),
    /alert-delivery-status result_summary must not include forbidden marker alert silenced/,
  );
});

test('recordEvidence rejects observability evidence without trace route and method binding', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['api-prometheus-metrics'] },
          { name: 'rust-prometheus-metrics', passed: true, target: 'https://rust.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          observabilityProbeReportProbe('trace-backend-search', { result_summary: observabilityProbeMarkerSummaries['trace-backend-search'].replace('route=/api/v1/ai/generate/study, ', '') }),
          observabilityProbeReportProbe('log-backend-trace-correlation'),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /trace-backend-search result_summary must include verified marker route=\/api\/v1\/ai\/generate\/study/,
  );
});

test('recordEvidence rejects observability evidence without Rust failure counters', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['api-prometheus-metrics'] },
          {
            name: 'rust-prometheus-metrics',
            passed: true,
            target: 'https://rust.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, scriptureforge_rust_engine_embedding_requests_total, scriptureforge_rust_engine_vector_search_requests_total, release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
          observabilityProbeReportProbe('trace-backend-search'),
          observabilityProbeReportProbe('log-backend-trace-correlation'),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /rust-prometheus-metrics result_summary must include verified marker scriptureforge_rust_engine_embedding_failures_total/,
  );
});

test('recordEvidence rejects observability evidence without API Rust dependency metrics', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          {
            name: 'api-prometheus-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, scriptureforge_http_requests_total, scriptureforge_http_request_duration_seconds_sum, scriptureforge_http_requests_total{, status=, websocket_active_connections_count, ai_inference_duration_seconds_sum, ai_inference_duration_seconds_count, release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
          { name: 'rust-prometheus-metrics', passed: true, target: 'https://rust.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          observabilityProbeReportProbe('trace-backend-search'),
          observabilityProbeReportProbe('log-backend-trace-correlation'),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /api-prometheus-metrics result_summary must include verified marker scriptureforge_dependency_operations_total/,
  );
});

test('recordEvidence rejects observability evidence without architecture metric profile proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          {
            name: 'api-prometheus-metrics',
            passed: true,
            target: 'https://api.staging.scriptureforge.ai/metrics',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, scriptureforge_http_requests_total, scriptureforge_http_request_duration_seconds_sum, scriptureforge_http_requests_total{, status=, scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success", scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success", release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
          { name: 'rust-prometheus-metrics', passed: true, target: 'https://rust.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          observabilityProbeReportProbe('trace-backend-search'),
          observabilityProbeReportProbe('log-backend-trace-correlation'),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /api-prometheus-metrics result_summary must include verified marker websocket_active_connections_count/,
  );
});

test('recordEvidence rejects observability evidence without full alert-rule coverage', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-ALERT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        alert_name: 'ScriptureForgeHighErrorRate',
        alert_receiver: 'staging-release',
        evidence_items: ['OBS-ALERT-001'],
        probes: [
          { name: 'dashboard-import', passed: true, target: 'https://grafana.staging.scriptureforge.ai/d/scriptureforge', status_code: 200, result_summary: observabilityProbeMarkerSummaries['dashboard-import'] },
          { name: 'alert-rules-loaded', passed: true, target: 'https://prometheus.staging.scriptureforge.ai/rules', status_code: 200, result_summary: observabilityProbeMarkerSummaries['alert-rules-loaded'].replace('ScriptureForgeRoomStreamFailures, ', '') },
          observabilityProbeReportProbe('alert-delivery-status', { target: 'https://alertmanager.staging.scriptureforge.ai/status' }),
          { name: 'telemetry-retention-policy', passed: true, target: 'https://observability.staging.scriptureforge.ai/retention', status_code: 200, result_summary: observabilityProbeMarkerSummaries['telemetry-retention-policy'] },
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-alerts',
    ),
    /alert-rules-loaded result_summary must include verified marker ScriptureForgeRoomStreamFailures/,
  );
});

test('recordEvidence rejects observability evidence without trace-scoped backend URLs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['api-prometheus-metrics'] },
          { name: 'rust-prometheus-metrics', passed: true, target: 'https://rust.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          observabilityProbeReportProbe('trace-backend-search', { target: 'https://traces.staging.scriptureforge.ai/search?service=scriptureforge-api' }),
          observabilityProbeReportProbe('log-backend-trace-correlation'),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /trace-backend-search target must include report trace_id/,
  );
});

test('recordEvidence rejects observability evidence from local telemetry surfaces', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        trace_id: observabilityTraceID,
        observed_route: '/api/v1/ai/generate/study',
        http_method: 'POST',
        tenant_id: 'org-staging',
        user_id: 'user-staging',
        role: 'admin',
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.scriptureforge.ai/collector', status_code: 200, result_summary: observabilityProbeMarkerSummaries['collector-otlp-config'] },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.scriptureforge.ai/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['api-prometheus-metrics'] },
          { name: 'rust-prometheus-metrics', passed: true, target: 'http://127.0.0.1:9102/metrics', status_code: 200, result_summary: observabilityProbeMarkerSummaries['rust-prometheus-metrics'] },
          observabilityProbeReportProbe('trace-backend-search'),
          observabilityProbeReportProbe('log-backend-trace-correlation'),
        ],
      },
      'artifacts/observabilityprobe.json',
      'go run ./tools/observabilityprobe -probe-otel',
    ),
    /rust-prometheus-metrics target must not be local\/self-test/,
  );
});

test('recordEvidence records production-grade security evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [
      { id: 'SEC-SECRETS-001', status: 'pending_external' },
      { id: 'SEC-DBUSER-001', status: 'pending_external' },
    ],
  };

  const artifactProbeNames = [
    'irsa-service-account',
    'secret-provider-class',
    'synced-secret-metadata-redacted',
    'iam-secrets-policy',
    'scoped-secrets-access-test',
  ];

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      evidence_items: ['SEC-SECRETS-001', 'SEC-DBUSER-001'],
      probes: [
        ...artifactProbeNames.map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.scriptureforge.ai/security/${name}.txt`,
          status_code: 200,
          result_summary: securityProbeMarkerSummaries[name],
        })),
        {
          name: 'database-scoped-user',
          passed: true,
          target: 'redacted-database-url',
          result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grants=SELECT,INSERT,UPDATE,DELETE; verified markers: staging artifact, release_candidate=abc123, service_version=scriptureforge-api:abc123',
        },
      ],
    },
    'artifacts/securityprobe.json',
    'go run ./tools/securityprobe -probe-secrets -probe-db-user',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
});

test('recordEvidence rejects secret evidence without concrete IAM role ARN markers', () => {
  const artifactProbeNames = [
    'irsa-service-account',
    'secret-provider-class',
    'synced-secret-metadata-redacted',
    'iam-secrets-policy',
    'scoped-secrets-access-test',
  ];

  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: artifactProbeNames.map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.scriptureforge.ai/security/${name}.txt`,
          status_code: 200,
          result_summary: name === 'irsa-service-account'
            ? securityProbeMarkerSummaries[name].replace('role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets', 'role_arn=arn:aws:iam::')
            : securityProbeMarkerSummaries[name],
        })),
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /irsa-service-account result_summary must include concrete IAM role ARN marker/,
  );
});

test('recordEvidence rejects secret evidence with mismatched role ARN markers', () => {
  const artifactProbeNames = [
    'irsa-service-account',
    'secret-provider-class',
    'synced-secret-metadata-redacted',
    'iam-secrets-policy',
    'scoped-secrets-access-test',
  ];

  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: artifactProbeNames.map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.scriptureforge.ai/security/${name}.txt`,
          status_code: 200,
          result_summary: name === 'iam-secrets-policy'
            ? securityProbeMarkerSummaries[name].replace('role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets', 'role_arn=arn:aws:iam::123456789012:role/scriptureforge-other-secrets')
            : securityProbeMarkerSummaries[name],
        })),
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /SEC-SECRETS-001 secret evidence role_arn values must match/,
  );
});

test('recordEvidence rejects security evidence for a different release candidate', () => {
  const artifactProbeNames = [
    'irsa-service-account',
    'secret-provider-class',
    'synced-secret-metadata-redacted',
    'iam-secrets-policy',
    'scoped-secrets-access-test',
  ];

  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        evidence_items: ['SEC-SECRETS-001'],
        probes: artifactProbeNames.map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.scriptureforge.ai/security/${name}.txt`,
          status_code: 200,
          result_summary: securityProbeMarkerSummaries[name]
            .replaceAll('release_candidate=abc123', 'release_candidate=def456')
            .replaceAll('service_version=scriptureforge-api:abc123', 'service_version=scriptureforge-api:def456'),
        })),
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /SEC-SECRETS-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects security evidence with local secret artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          { name: 'irsa-service-account', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/service-account.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['irsa-service-account'] },
          { name: 'secret-provider-class', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/secret-provider.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['secret-provider-class'] },
          { name: 'synced-secret-metadata-redacted', passed: true, target: 'http://localhost/security/synced-secret.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['synced-secret-metadata-redacted'] },
          { name: 'iam-secrets-policy', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['iam-secrets-policy'] },
          { name: 'scoped-secrets-access-test', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'] },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /synced-secret-metadata-redacted target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence rejects security evidence with duplicate secret artifact URLs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          { name: 'irsa-service-account', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/shared-secret-proof.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['irsa-service-account'] },
          { name: 'secret-provider-class', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/shared-secret-proof.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['secret-provider-class'] },
          { name: 'synced-secret-metadata-redacted', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/synced-secret.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['synced-secret-metadata-redacted'] },
          { name: 'iam-secrets-policy', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['iam-secrets-policy'] },
          { name: 'scoped-secrets-access-test', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt', status_code: 200, result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'] },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /SEC-SECRETS-001 secret-provider-class target must be a distinct artifact URL from irsa-service-account target/,
  );
});

test('recordEvidence rejects secret evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          {
            name: 'irsa-service-account',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/service-account.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['irsa-service-account'].replace('trust policy, ', ''),
          },
          {
            name: 'secret-provider-class',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/secret-provider.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['secret-provider-class'],
          },
          {
            name: 'synced-secret-metadata-redacted',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/synced-secret.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['synced-secret-metadata-redacted'],
          },
          {
            name: 'iam-secrets-policy',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['iam-secrets-policy'],
          },
          {
            name: 'scoped-secrets-access-test',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'],
          },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /irsa-service-account result_summary must include verified marker trust policy/,
  );
});

test('recordEvidence rejects secret evidence without staging artifact provenance', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          {
            name: 'irsa-service-account',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/service-account.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['irsa-service-account'].replace('staging artifact, ', ''),
          },
          {
            name: 'secret-provider-class',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/secret-provider.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['secret-provider-class'],
          },
          {
            name: 'synced-secret-metadata-redacted',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/synced-secret.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['synced-secret-metadata-redacted'],
          },
          {
            name: 'iam-secrets-policy',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['iam-secrets-policy'],
          },
          {
            name: 'scoped-secrets-access-test',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'],
          },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /irsa-service-account result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects secret evidence without scoped IAM markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          {
            name: 'irsa-service-account',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/service-account.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['irsa-service-account'],
          },
          {
            name: 'secret-provider-class',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/secret-provider.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['secret-provider-class'],
          },
          {
            name: 'synced-secret-metadata-redacted',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/synced-secret.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['synced-secret-metadata-redacted'],
          },
          {
            name: 'iam-secrets-policy',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets, secretsmanager:GetSecretValue, secretsmanager:DescribeSecret, arn:aws:secretsmanager:',
          },
          {
            name: 'scoped-secrets-access-test',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'],
          },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /iam-secrets-policy result_summary must include verified marker scoped resource/,
  );
});

test('recordEvidence rejects secret evidence without SecretProviderClass object-sync markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          {
            name: 'irsa-service-account',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/service-account.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['irsa-service-account'],
          },
          {
            name: 'secret-provider-class',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/secret-provider.txt',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, namespace=staging, service_account=scriptureforge-api, role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets, SecretProviderClass, secrets-store.csi.k8s.io, DATABASE_URL, JWT_SECRET_KEY, OPENAI_API_KEY, ZOOM_WEBHOOK_SECRET_TOKEN',
          },
          {
            name: 'synced-secret-metadata-redacted',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/synced-secret.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['synced-secret-metadata-redacted'],
          },
          {
            name: 'iam-secrets-policy',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['iam-secrets-policy'],
          },
          {
            name: 'scoped-secrets-access-test',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'],
          },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /secret-provider-class result_summary must include verified marker objects/,
  );
});

test('recordEvidence rejects secret evidence without synced-secret redaction markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          {
            name: 'irsa-service-account',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/service-account.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['irsa-service-account'],
          },
          {
            name: 'secret-provider-class',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/secret-provider.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['secret-provider-class'],
          },
          {
            name: 'synced-secret-metadata-redacted',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/synced-secret.txt',
            status_code: 200,
            result_summary: 'got HTTP 200; verified markers: staging artifact, namespace=staging, scriptureforge-runtime-secrets, DATABASE_URL, JWT_SECRET_KEY',
          },
          {
            name: 'iam-secrets-policy',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['iam-secrets-policy'],
          },
          {
            name: 'scoped-secrets-access-test',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'],
          },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /synced-secret-metadata-redacted result_summary must include verified marker type/,
  );
});

test('recordEvidence rejects secret evidence without synced-secret ownership markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          {
            name: 'irsa-service-account',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/service-account.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['irsa-service-account'],
          },
          {
            name: 'secret-provider-class',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/secret-provider.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['secret-provider-class'],
          },
          {
            name: 'synced-secret-metadata-redacted',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/synced-secret.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['synced-secret-metadata-redacted']
              .replace(', ownerReferences', '')
              .replace(', secrets-store.csi.k8s.io/managed=true', ''),
          },
          {
            name: 'iam-secrets-policy',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/iam.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['iam-secrets-policy'],
          },
          {
            name: 'scoped-secrets-access-test',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/security/access-test.txt',
            status_code: 200,
            result_summary: securityProbeMarkerSummaries['scoped-secrets-access-test'],
          },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /synced-secret-metadata-redacted result_summary must include verified marker ownerReferences/,
  );
});

test('recordEvidence rejects database user evidence without non-admin role proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false bypassrls=false createrole=false',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /database-scoped-user summary must prove createdb=false/,
  );
});

test('recordEvidence rejects database user evidence without scriptureforge_app principal proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "tenant_app" in 25ms; superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grants=SELECT,INSERT,UPDATE,DELETE; verified markers: staging artifact, release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /database-scoped-user summary must prove connected as scriptureforge_app/,
  );
});

test('recordEvidence rejects database user evidence without bypass RLS denial proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false createrole=false createdb=false privileged_operation_denied=true; verified markers: staging artifact, release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /database-scoped-user summary must prove bypassrls=false/,
  );
});

test('recordEvidence rejects database user evidence without denied privileged operation proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false bypassrls=false createrole=false createdb=false; verified markers: staging artifact, release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /database-scoped-user summary must prove privileged_operation_denied=true/,
  );
});

test('recordEvidence rejects database user evidence without application grant proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true; verified markers: staging artifact, release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /database-scoped-user summary must prove app_grants_verified=true/,
  );
});

test('recordEvidence rejects database user evidence without staging artifact provenance', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grants=SELECT,INSERT,UPDATE,DELETE; verified markers: release_candidate=abc123, service_version=scriptureforge-api:abc123',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /database-scoped-user result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects database user evidence for a different release candidate', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grants=SELECT,INSERT,UPDATE,DELETE; verified markers: staging artifact, release_candidate=def456, service_version=scriptureforge-api:def456',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /SEC-DBUSER-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence records production-grade resilience evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [
      { id: 'DR-ROLLBACK-001', status: 'pending_external' },
      { id: 'DR-BACKUP-001', status: 'pending_external' },
    ],
  };

  const probeNames = [
    'api-ready-before-rollback',
    'rollback-rollout-artifact',
    'api-ready-after-rollback',
    'degradation-drill-artifact',
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ];

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      evidence_items: ['DR-ROLLBACK-001', 'DR-BACKUP-001'],
      probes: resilienceProbeReportProbes(probeNames),
    },
    'artifacts/resilienceprobe.json',
    'go run ./tools/resilienceprobe -probe-rollback -probe-backup',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
});

test('recordEvidence rejects resilience evidence for a different release candidate', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'DR-ROLLBACK-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        evidence_items: ['DR-ROLLBACK-001'],
        probes: [
          'api-ready-before-rollback',
          'rollback-rollout-artifact',
          'api-ready-after-rollback',
          'degradation-drill-artifact',
        ].map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.scriptureforge.ai/resilience/${name}.txt`,
          status_code: 200,
          result_summary: resilienceProbeMarkerSummaries[name]
            .replaceAll('release_candidate=abc123', 'release_candidate=def456')
            .replaceAll('service_version=scriptureforge-api:abc123', 'service_version=scriptureforge-api:def456'),
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-rollback',
    ),
    /DR-ROLLBACK-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects resilience evidence from local readiness targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-ROLLBACK-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DR-ROLLBACK-001'],
        probes: [
          { name: 'api-ready-before-rollback', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/rollback/ready-before.json', status_code: 200, result_summary: resilienceProbeMarkerSummaries['api-ready-before-rollback'] },
          { name: 'rollback-rollout-artifact', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/rollback/rollout.txt', status_code: 200, result_summary: resilienceProbeMarkerSummaries['rollback-rollout-artifact'] },
          { name: 'api-ready-after-rollback', passed: true, target: 'http://127.0.0.1:8080/ready', status_code: 200, result_summary: resilienceProbeMarkerSummaries['api-ready-after-rollback'] },
          { name: 'degradation-drill-artifact', passed: true, target: 'https://artifacts.staging.scriptureforge.ai/rollback/degradation.txt', status_code: 200, result_summary: resilienceProbeMarkerSummaries['degradation-drill-artifact'] },
        ],
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-rollback',
    ),
    /api-ready-after-rollback target must be an HTTPS staging URL or artifact URL/,
  );
});

test('recordEvidence rejects rollback evidence with duplicate artifact URLs', () => {
  const probeNames = [
    'api-ready-before-rollback',
    'rollback-rollout-artifact',
    'api-ready-after-rollback',
    'degradation-drill-artifact',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-ROLLBACK-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-ROLLBACK-001'],
        probes: probeNames.map((name) => ({
          name,
          passed: true,
          target: name === 'degradation-drill-artifact'
            ? 'https://artifacts.staging.scriptureforge.ai/resilience/rollback-rollout-artifact.txt'
            : `https://artifacts.staging.scriptureforge.ai/resilience/${name}.txt`,
          status_code: 200,
          result_summary: resilienceProbeMarkerSummaries[name],
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-rollback',
    ),
    /DR-ROLLBACK-001 degradation-drill-artifact must be a distinct artifact URL from rollback-rollout-artifact/,
  );
});

test('recordEvidence rejects backup evidence with duplicate artifact URLs', () => {
  const probeNames = [
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-BACKUP-001'],
        probes: resilienceProbeReportProbes(probeNames, (name) => ({
          target: name === 'restored-database-smoke'
            ? 'https://artifacts.staging.scriptureforge.ai/resilience/restore-drill-artifact.txt'
            : `https://artifacts.staging.scriptureforge.ai/resilience/${name}.txt`,
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /DR-BACKUP-001 restored-database-smoke must be a distinct artifact URL from restore-drill-artifact/,
  );
});

test('recordEvidence rejects resilience evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DR-BACKUP-001'],
        probes: resilienceProbeReportProbes([
          'backup-snapshot-artifact',
          'restore-drill-artifact',
          'restored-database-smoke',
        ], (name) => ({
          target: name === 'backup-snapshot-artifact'
            ? 'https://artifacts.staging.scriptureforge.ai/backup/snapshot.txt'
            : name === 'restore-drill-artifact'
              ? 'https://artifacts.staging.scriptureforge.ai/backup/restore.txt'
              : 'https://artifacts.staging.scriptureforge.ai/backup/restored-smoke.txt',
          result_summary: name === 'restore-drill-artifact'
            ? resilienceProbeMarkerSummaries['restore-drill-artifact'].replace('checksum', '')
            : resilienceProbeMarkerSummaries[name],
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /restore-drill-artifact result_summary must include verified marker checksum/,
  );
});

test('recordEvidence rejects resilience evidence with admitted failed drill summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-ROLLBACK-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-ROLLBACK-001'],
        probes: resilienceProbeReportProbes([
          'api-ready-before-rollback',
          'rollback-rollout-artifact',
          'api-ready-after-rollback',
          'degradation-drill-artifact',
        ], (name) => ({
          result_summary: name === 'rollback-rollout-artifact'
            ? `${resilienceProbeMarkerSummaries[name]}; rollback failed`
            : resilienceProbeMarkerSummaries[name],
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-rollback',
    ),
    /rollback-rollout-artifact result_summary must not include forbidden marker rollback failed/,
  );
});

test('recordEvidence rejects rollback evidence without distinct artifact marker', () => {
  const probeNames = [
    'api-ready-before-rollback',
    'rollback-rollout-artifact',
    'api-ready-after-rollback',
    'degradation-drill-artifact',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-ROLLBACK-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-ROLLBACK-001'],
        probes: probeNames.map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.scriptureforge.ai/resilience/${name}.txt`,
          status_code: 200,
          result_summary: name === 'degradation-drill-artifact'
            ? resilienceProbeMarkerSummaries[name].replace(', distinct_rollback_artifacts=true', '')
            : resilienceProbeMarkerSummaries[name],
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-rollback',
    ),
    /degradation-drill-artifact result_summary must include verified marker distinct_rollback_artifacts=true/,
  );
});

test('recordEvidence rejects backup evidence without distinct artifact marker', () => {
  const probeNames = [
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-BACKUP-001'],
        probes: resilienceProbeReportProbes(probeNames, (name) => ({
          result_summary: name === 'restored-database-smoke'
            ? resilienceProbeMarkerSummaries[name].replace(', distinct_backup_artifacts=true', '')
            : resilienceProbeMarkerSummaries[name],
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /restored-database-smoke result_summary must include verified marker distinct_backup_artifacts=true/,
  );
});

test('recordEvidence rejects resilience evidence without staging artifact marker', () => {
  const probeNames = [
    'api-ready-before-rollback',
    'rollback-rollout-artifact',
    'api-ready-after-rollback',
    'degradation-drill-artifact',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-ROLLBACK-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DR-ROLLBACK-001'],
        probes: probeNames.map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.scriptureforge.ai/resilience/${name}.txt`,
          status_code: 200,
          result_summary: resilienceProbeMarkerSummaries[name].replace('staging artifact; ', ''),
        })),
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-rollback',
    ),
    /api-ready-before-rollback result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects rollback evidence without version linkage markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-ROLLBACK-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DR-ROLLBACK-001'],
        probes: [
          {
            name: 'api-ready-before-rollback',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/rollback/ready-before.json',
            status_code: 200,
            result_summary: 'got HTTP 200; staging artifact; verified markers: ready, service_version, deployment_environment',
          },
          {
            name: 'rollback-rollout-artifact',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/rollback/rollout.txt',
            status_code: 200,
            result_summary: resilienceProbeMarkerSummaries['rollback-rollout-artifact'],
          },
          {
            name: 'api-ready-after-rollback',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/rollback/ready-after.json',
            status_code: 200,
            result_summary: resilienceProbeMarkerSummaries['api-ready-after-rollback'],
          },
          {
            name: 'degradation-drill-artifact',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/rollback/degradation.txt',
            status_code: 200,
            result_summary: resilienceProbeMarkerSummaries['degradation-drill-artifact'],
          },
        ],
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-rollback',
    ),
    /api-ready-before-rollback result_summary must include verified marker pre_rollback_version/,
  );
});

test('recordEvidence rejects backup evidence without restored RLS and no-plaintext proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DR-BACKUP-001'],
        probes: [
          resilienceProbeReportProbe('backup-snapshot-artifact', {
            target: 'https://artifacts.staging.scriptureforge.ai/backup/snapshot.txt',
          }),
          resilienceProbeReportProbe('restore-drill-artifact', {
            target: 'https://artifacts.staging.scriptureforge.ai/backup/restore.txt',
          }),
          {
            name: 'restored-database-smoke',
            passed: true,
            target: 'https://artifacts.staging.scriptureforge.ai/backup/restored-smoke.txt',
            status_code: 200,
            result_summary: 'got HTTP 200; staging artifact; verified markers: smoke passed, restored database, tenant, journal',
          },
        ],
      },
      'artifacts/resilienceprobe.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /restored-database-smoke result_summary must include verified marker auth/,
  );
});

test('recordEvidence rejects backup evidence without recovery objective markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DR-BACKUP-001'],
        probes: [
          resilienceProbeReportProbe('backup-snapshot-artifact', {
            target: 'https://artifacts.staging.scriptureforge.ai/backup/snapshot.txt',
            result_summary: resilienceProbeMarkerSummaries['backup-snapshot-artifact'].replace(', rpo_minutes=15', ''),
          }),
          resilienceProbeReportProbe('restore-drill-artifact', {
            target: 'https://artifacts.staging.scriptureforge.ai/backup/restore.txt',
          }),
          resilienceProbeReportProbe('restored-database-smoke', {
            target: 'https://artifacts.staging.scriptureforge.ai/backup/restored-smoke.txt',
          }),
        ],
      },
      'artifacts/resilienceprobe-backup.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /backup-snapshot-artifact result_summary must include verified marker rpo_minutes/,
  );
});

test('recordEvidence rejects backup evidence without structured snapshot and recovery fields', () => {
  const probeNames = [
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-BACKUP-001'],
        probes: resilienceProbeReportProbes(probeNames, (name) => (
          name === 'backup-snapshot-artifact' ? { snapshot_id: '', rpo_minutes: undefined } : {}
        )),
      },
      'artifacts/resilienceprobe-backup.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /backup-snapshot-artifact probe must include structured snapshot_id/,
  );
});

test('recordEvidence rejects backup evidence when structured restore fields do not match summary', () => {
  const probeNames = [
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-BACKUP-001'],
        probes: resilienceProbeReportProbes(probeNames, (name) => (
          name === 'restore-drill-artifact' ? { restore_job_id: 'restore-999' } : {}
        )),
      },
      'artifacts/resilienceprobe-backup.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /restore-drill-artifact result_summary must include verified marker restore_job_id=restore-999/,
  );
});

test('recordEvidence rejects backup evidence when restore source snapshot differs from backup snapshot', () => {
  const probeNames = [
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-BACKUP-001'],
        probes: resilienceProbeReportProbes(probeNames, (name) => (
          name === 'restore-drill-artifact'
            ? {
                source_snapshot_id: 'snap-other',
                result_summary: resilienceProbeMarkerSummaries['restore-drill-artifact'].replace('source snapshot_id=snap-123', 'source snapshot_id=snap-other'),
              }
            : {}
        )),
      },
      'artifacts/resilienceprobe-backup.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /DR-BACKUP-001 restore-drill-artifact source_snapshot_id must match backup-snapshot-artifact snapshot_id/,
  );
});

test('recordEvidence rejects backup evidence when restore duration exceeds RTO', () => {
  const probeNames = [
    'backup-snapshot-artifact',
    'restore-drill-artifact',
    'restored-database-smoke',
  ];
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DR-BACKUP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['DR-BACKUP-001'],
        probes: resilienceProbeReportProbes(probeNames, (name) => (
          name === 'restore-drill-artifact'
            ? {
                restore_duration_minutes: 45,
                result_summary: resilienceProbeMarkerSummaries['restore-drill-artifact'].replace('restore_duration_minutes=18', 'restore_duration_minutes=45'),
              }
            : {}
        )),
      },
      'artifacts/resilienceprobe-backup.json',
      'go run ./tools/resilienceprobe -probe-backup',
    ),
    /restore-drill-artifact restore_duration_minutes must be less than or equal to rto_minutes/,
  );
});

test('recordEvidence rejects failed probe reports', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: false,
        evidence_items: ['DEPLOY-TLS-001'],
      },
      'artifact.json',
      'probe',
    ),
    /threshold_pass must be true/,
  );
});

test('recordEvidence rejects under-target HTTP performance evidence', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 100,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 120,
        p99_ms: 50,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 min_rps 100 is below required 5000/,
  );
});

test('recordEvidence rejects local performance evidence targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        target: 'http://127.0.0.1:8080/health',
        min_rps: 5000,
        max_p99_ms: 200,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        rps: 6000,
        p99_ms: 80,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /target must not be local\/self-test/,
  );
});

test('recordEvidence rejects private-network performance evidence targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        target: 'https://10.0.0.15/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 6000,
        p99_ms: 80,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /target must not be local\/self-test/,
  );
});

test('recordEvidence rejects reserved placeholder performance evidence targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        target: 'https://api.staging.example/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 6000,
        p99_ms: 80,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /reserved placeholder hosts are not accepted/,
  );
});

test('recordEvidence rejects private IPv6 performance evidence targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        target: 'https://[fd00::15]/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 6000,
        p99_ms: 80,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /target must not be local\/self-test/,
  );
});

test('recordEvidence rejects IPv4-mapped private IPv6 performance evidence targets', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        target: 'https://[::ffff:10.0.0.15]/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 6000,
        p99_ms: 80,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /target must not be local\/self-test/,
  );
});

test('recordEvidence records production-grade HTTP performance evidence', () => {
  const manifest = {
    items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      evidence_items: ['PERF-HTTP-001'],
      evidence_profile: 'staging_http',
      target: 'https://api.staging.scriptureforge.ai/health',
      min_rps: 5000,
      max_p99_ms: 200,
      production_target_rps: 5000,
      production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      threshold_failures: [],
        duration_ms: 60000,
      rps: 5200,
      p99_ms: 180,
      http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
      dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
      result_summary: performanceReportSummaries.http,
    },
    'artifacts/load-http.json',
    'go run ./tools/loadtest -target=https://api.staging.scriptureforge.ai/health -min-rps=5000 -max-p99=200ms',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects performance reports for a different release candidate', () => {
  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: performanceReportSummaries.http,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest -target=https://api.staging.scriptureforge.ai/health',
    ),
    /PERF-HTTP-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects HTTP performance evidence without staging telemetry artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        result_summary: performanceReportSummaries.http,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /must include HTTPS http_replica_artifact_url/,
  );
});

test('recordEvidence rejects HTTP performance evidence with duplicate artifact URLs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/shared-http-proof.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/shared-http-proof.txt',
        result_summary: performanceReportSummaries.http,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 dependency_telemetry_artifact_url must be a distinct artifact URL from http_replica_artifact_url/,
  );
});

test('recordEvidence rejects HTTP performance evidence with canonical duplicate artifact URLs', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://ARTIFACTS.staging.scriptureforge.ai:443/load/shared-http-proof.txt?b=2&a=1',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/shared-http-proof.txt?a=1&b=2',
        result_summary: performanceReportSummaries.http,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 dependency_telemetry_artifact_url must be a distinct artifact URL from http_replica_artifact_url/,
  );
});

test('recordEvidence records production-grade WebSocket performance and Redis evidence together', () => {
  const manifest = {
    items: [
      { id: 'PERF-WS-001', status: 'pending_external' },
      { id: 'DATA-REDIS-001', status: 'pending_external' },
    ],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
      evidence_profile: 'staging_websocket',
      target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
      min_rps: 500,
      max_p99_ms: 200,
      production_target_rps: 500,
      production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      threshold_failures: [],
        duration_ms: 60000,
      rps: 620,
      p99_ms: 140,
      ws_origin: 'https://web.staging.scriptureforge.ai',
      ws_room_id: 'room-1',
      ws_authenticated: true,
      ws_expected_events: 30000,
      ws_unique_sequences: 30000,
      ws_min_sequence: 1,
      ws_max_sequence: 30000,
      ws_polling_latest_sequence: 30000,
      ws_sequence_contiguous: true,
      ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
      ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
      ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
      redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
      result_summary: performanceReportSummaries.websocket,
    },
    'artifacts/load-ws.json',
    'go run ./tools/loadtest -websocket -target=wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
});

test('recordEvidence rejects WebSocket performance evidence with duplicate artifact URLs', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 ws_polling_artifact_url must be a distinct artifact URL from ws_reconnect_artifact_url/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without distinct artifact marker', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace(' ws_distinct_artifacts=true,', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker ws_distinct_artifacts=true/,
  );
});

test('recordEvidence rejects WebSocket performance evidence with failed threshold summary', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace('threshold_pass=true', 'threshold_pass=false'),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker threshold_pass=true/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without production target summary markers', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace(' production_target_rps=500 production_target_p99_ms=200', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker production_target_rps=500/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without room binding', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace(' ws_room_id=room-1', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker ws_room_id=/,
  );
});

test('recordEvidence rejects WebSocket performance evidence with mismatched room binding summary', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-2',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /DATA-REDIS-001 room binding result_summary must include verified marker ws_room_id=room-2/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without polling latest sequence binding', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace(' ws_polling_latest_sequence=30000', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /DATA-REDIS-001 polling fallback result_summary must include verified marker ws_polling_latest_sequence=30000/,
  );
});

test('recordEvidence rejects WebSocket performance evidence when polling latest sequence lags max sequence', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 29999,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /DATA-REDIS-001 polling latest sequence must equal maximum sequence/,
  );
});

test('recordEvidence rejects performance evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_count: 2,
        dependency_postgres_p99_ms: 32,
        dependency_redis_p99_ms: 18,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: 'observed rps and p99 passed http_replica_count=2 dependency_postgres_p99_ms=32 dependency_redis_p99_ms=18',
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 result_summary must include verified marker staging_http/,
  );
});

test('recordEvidence rejects HTTP performance evidence with failed threshold summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: performanceReportSummaries.http.replace('threshold_pass=true', 'threshold_pass=false'),
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 result_summary must include verified marker threshold_pass=true/,
  );
});

test('recordEvidence rejects HTTP performance evidence with admitted threshold failure summary', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: `${performanceReportSummaries.http}; threshold failed`,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 result_summary must not include forbidden marker threshold failed/,
  );
});

test('recordEvidence rejects HTTP performance evidence without production target summary markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: performanceReportSummaries.http.replace(' production_target_rps=5000 production_target_p99_ms=200', ''),
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 result_summary must include verified marker production_target_rps=5000/,
  );
});

test('recordEvidence rejects HTTP performance evidence without artifact verification markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: performanceReportSummaries.http.replace('dependency_telemetry_artifact_verified', ''),
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 result_summary must include verified marker dependency_telemetry_artifact_verified/,
  );
});

test('recordEvidence rejects HTTP performance evidence without dependency latency artifact marker', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: performanceReportSummaries.http.replace(', dependency_latency_artifact_verified=true', ''),
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 result_summary must include verified marker dependency_latency_artifact_verified=true/,
  );
});

test('recordEvidence rejects HTTP performance evidence with weak structured artifact values', () => {
  for (const [report, expected] of [
    [
      httpPerformanceReport({
        http_replica_count: 1,
        result_summary: performanceReportSummaries.http
          .replace('http_replica_count=2', 'http_replica_count=1')
          .replace('http_replica_count=2', 'http_replica_count=1'),
      }),
      /PERF-HTTP-001 http_replica_count 1 must prove at least 2 replicas/,
    ],
    [
      httpPerformanceReport({
        dependency_postgres_p99_ms: 250,
        result_summary: performanceReportSummaries.http
          .replace('dependency_postgres_p99_ms=32', 'dependency_postgres_p99_ms=250')
          .replace('dependency_postgres_p99_ms=32', 'dependency_postgres_p99_ms=250'),
      }),
      /PERF-HTTP-001 dependency_postgres_p99_ms 250 must be <= 200/,
    ],
    [
      httpPerformanceReport({
        dependency_redis_p99_ms: 250,
        result_summary: performanceReportSummaries.http
          .replace('dependency_redis_p99_ms=18', 'dependency_redis_p99_ms=250')
          .replace('dependency_redis_p99_ms=18', 'dependency_redis_p99_ms=250'),
      }),
      /PERF-HTTP-001 dependency_redis_p99_ms 250 must be <= 200/,
    ],
  ]) {
    assert.throws(
      () => recordEvidence(
        { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
        report,
        'artifacts/load-http.json',
        'go run ./tools/loadtest',
      ),
      expected,
    );
  }
});

test('recordEvidence rejects performance evidence without release linkage fields', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        evidence_profile: 'staging_http',
        target: 'https://api.staging.scriptureforge.ai/health',
        min_rps: 5000,
        max_p99_ms: 200,
        production_target_rps: 5000,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        threshold_failures: [],
        duration_ms: 60000,
        rps: 5200,
        p99_ms: 180,
        http_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt',
        dependency_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt',
        result_summary: performanceReportSummaries.http,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /PERF-HTTP-001 report must include release_candidate/,
  );
});

test('recordEvidence rejects under-target WebSocket performance evidence', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 100,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 42,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 10,
        ws_unique_sequences: 10,
        ws_min_sequence: 1,
        ws_max_sequence: 10,
        ws_polling_latest_sequence: 10,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 min_rps 100 is below required 500/,
  );
});

test('recordEvidence rejects WebSocket performance evidence below minimum duration', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 1000,
        rps: 620,
        p99_ms: 42,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace('duration_ms=60000', 'duration_ms=1000'),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 duration_ms 1000 is below required 60000/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without HTTPS origin proof', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'http://localhost',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 report must include HTTPS ws_origin/,
  );
});

test('recordEvidence rejects WebSocket and Redis performance evidence without staging artifacts', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        result_summary: performanceReportSummaries.websocket,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /must include HTTPS ws_replica_artifact_url/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without reconnect and polling artifacts', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 report must include HTTPS ws_reconnect_artifact_url/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without artifact verification markers', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace('ws_reconnect_artifact_verified, ', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker ws_reconnect_artifact_verified/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without reconnect sequence continuity marker', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace('ws_reconnect_sequence_continues=true, ', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker ws_reconnect_sequence_continues=true/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without polling artifact sequence validation marker', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace('ws_polling_artifact_latest_sequence_validated=true, ', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker ws_polling_artifact_latest_sequence_validated=true/,
  );
});

test('recordEvidence rejects WebSocket performance evidence without exact polling sequence match marker', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 30000,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: true,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket.replace('ws_polling_artifact_latest_sequence_matches_run=true, ', ''),
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /PERF-WS-001 result_summary must include verified marker ws_polling_artifact_latest_sequence_matches_run=true/,
  );
});

test('recordEvidence rejects Redis sequencing evidence without contiguous sequence proof', () => {
  assert.throws(
    () => recordEvidence(
      {
        items: [
          { id: 'PERF-WS-001', status: 'pending_external' },
          { id: 'DATA-REDIS-001', status: 'pending_external' },
        ],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-WS-001', 'DATA-REDIS-001'],
        evidence_profile: 'staging_websocket',
        target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        production_target_rps: 500,
        production_target_p99_ms: 200,
        production_min_duration_ms: 60000,
        production_min_ws_events: 30000,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        threshold_failures: [],
        duration_ms: 60000,
        rps: 620,
        p99_ms: 140,
        ws_origin: 'https://web.staging.scriptureforge.ai',
        ws_room_id: 'room-1',
        ws_authenticated: true,
        ws_expected_events: 30000,
        ws_unique_sequences: 399,
        ws_min_sequence: 1,
        ws_max_sequence: 30000,
        ws_polling_latest_sequence: 30000,
        ws_sequence_contiguous: false,
        ws_replica_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt',
        ws_reconnect_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt',
        ws_polling_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt',
        redis_telemetry_artifact_url: 'https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt',
        result_summary: performanceReportSummaries.websocket,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /must prove ws_sequence_contiguous=true/,
  );
});

test('recordEvidence rejects WebSocket performance evidence with weak structured artifact values', () => {
  for (const [report, expected] of [
    [
      websocketPerformanceReport({
        ws_replica_count: 1,
        result_summary: performanceReportSummaries.websocket
          .replace('ws_replica_count=2', 'ws_replica_count=1')
          .replace('ws_replica_count=2', 'ws_replica_count=1'),
      }),
      /PERF-WS-001 ws_replica_count 1 must prove at least 2 replicas/,
    ],
    [
      websocketPerformanceReport({
        room_broadcast_drops: 1,
      }),
      /DATA-REDIS-001 room_broadcast_drops must equal 0/,
    ],
  ]) {
    assert.throws(
      () => recordEvidence(
        {
          items: [
            { id: 'PERF-WS-001', status: 'pending_external' },
            { id: 'DATA-REDIS-001', status: 'pending_external' },
          ],
        },
        report,
        'artifacts/load-ws.json',
        'go run ./tools/loadtest -websocket',
      ),
      expected,
    );
  }
});

test('recordEvidence records production-grade abuse evidence', () => {
  const manifest = {
    release_candidate: 'abc123',
    items: [{ id: 'ABUSE-LIMIT-001', status: 'pending_external' }],
  };

  const probes = abuseProbeReportProbes();

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      api_target: 'https://api.staging.scriptureforge.ai',
      web_origin: 'https://app.staging.scriptureforge.ai',
      config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
      config_artifact_verified: true,
      config_artifact_summary: abuseConfigSummary,
      threshold_pass: true,
      release_candidate: 'abc123',
      service_version: 'scriptureforge-api:abc123',
      evidence_items: ['ABUSE-LIMIT-001'],
      probes,
    },
    'artifacts/abuseprobe.json',
    'go run ./tools/abuseprobe -api-base=https://api.staging.scriptureforge.ai',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.match(updated.items[0].evidence[0].result_summary, /config_artifact_verified=true/);
  assert.match(updated.items[0].evidence[0].result_summary, /distinct_abuse_artifacts=true/);
});

test('recordEvidence rejects abuse profile summaries without staging artifact provenance', () => {
  const probes = abuseProbeReportProbes((name) => ({
    result_summary: name === 'journal-rate-limit'
        ? abuseProbeMarkerSummaries[name].replace('staging artifact, ', '')
        : abuseProbeMarkerSummaries[name],
  }));

  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'ABUSE-LIMIT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes,
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe -api-base=https://api.staging.scriptureforge.ai',
    ),
    /journal-rate-limit result_summary must include verified marker staging artifact/,
  );
});

test('recordEvidence rejects abuse config summaries without concrete assignment markers', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary.replace('ABUSE_LIMIT_AI_REQUESTS=2', 'ABUSE_LIMIT_AI_REQUESTS'),
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /ABUSE-LIMIT-001 config_artifact_summary result_summary must include verified marker ABUSE_LIMIT_AI_REQUESTS=/,
  );
});

test('recordEvidence rejects abuse config summaries with zero assignment values', () => {
  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary.replace('ABUSE_LIMIT_AI_REQUESTS=2', 'ABUSE_LIMIT_AI_REQUESTS=0'),
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /ABUSE-LIMIT-001 config_artifact_summary ABUSE_LIMIT_AI_REQUESTS must be a positive integer/,
  );
});

test('recordEvidence rejects abuse config artifacts hosted on the API target', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://api.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /config_artifact_url must use a distinct host from api_target/,
  );
});

test('recordEvidence rejects abuse config artifacts hosted on a canonical API target alias', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://API.Staging.ScriptureForge.AI.',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://api.staging.scriptureforge.ai./abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /config_artifact_url must use a distinct host from api_target/,
  );
});

test('recordEvidence rejects abuse config artifacts hosted on the web origin', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://app.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /config_artifact_url must use a distinct host from web_origin/,
  );
});

test('recordEvidence rejects abuse config artifacts hosted on a canonical web origin alias', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://APP.staging.scriptureforge.ai.',
        config_artifact_url: 'https://app.staging.scriptureforge.ai./abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /config_artifact_url must use a distinct host from web_origin/,
  );
});

test('recordEvidence rejects abuse evidence for a different release candidate', () => {
  const staleProbeSummaries = Object.fromEntries(
    Object.entries(abuseProbeMarkerSummaries)
      .map(([name, summary]) => [
        name,
        summary
          .replaceAll('release_candidate=abc123', 'release_candidate=def456')
          .replaceAll('service_version=scriptureforge-api:abc123', 'service_version=scriptureforge-api:def456'),
      ]),
  );
  const probes = abuseProbeReportProbes((name) => ({
    result_summary: staleProbeSummaries[name],
  }));

  assert.throws(
    () => recordEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'ABUSE-LIMIT-001', status: 'pending_external' }],
      },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary
          .replaceAll('release_candidate=abc123', 'release_candidate=def456')
          .replaceAll('service_version=scriptureforge-api:abc123', 'service_version=scriptureforge-api:def456'),
        threshold_pass: true,
        release_candidate: 'def456',
        service_version: 'scriptureforge-api:def456',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes,
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe -api-base=https://api.staging.scriptureforge.ai',
    ),
    /ABUSE-LIMIT-001 report release_candidate must match manifest release_candidate/,
  );
});

test('recordEvidence rejects abuse evidence with weak rate-limit header values', () => {
  for (const { field, value, message } of [
    { field: 'retry_after', value: '0', message: /auth-rate-limit Retry-After must be a positive integer/ },
    { field: 'rate_limit', value: '0', message: /auth-rate-limit X-RateLimit-Limit must be a positive integer/ },
    { field: 'rate_limit_remaining', value: '1', message: /auth-rate-limit X-RateLimit-Remaining must equal 0/ },
    { field: 'rate_limit_reset', value: '0', message: /auth-rate-limit X-RateLimit-Reset must be a positive integer/ },
  ]) {
    const probes = abuseProbeReportProbes();
    probes[0][field] = value;

    assert.throws(
      () => recordEvidence(
        { items: [{ id: 'ABUSE-LIMIT-001', status: 'pending_external' }] },
        {
          observed_at: '2026-06-25T12:00:00Z',
          api_target: 'https://api.staging.scriptureforge.ai',
          web_origin: 'https://app.staging.scriptureforge.ai',
          config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
          config_artifact_verified: true,
          config_artifact_summary: abuseConfigSummary,
          threshold_pass: true,
          release_candidate: 'abc123',
          service_version: 'scriptureforge-api:abc123',
          evidence_items: ['ABUSE-LIMIT-001'],
          probes,
        },
        'artifacts/abuseprobe.json',
        'go run ./tools/abuseprobe -api-base=https://api.staging.scriptureforge.ai',
      ),
      message,
    );
  }
});

test('recordEvidence rejects abuse evidence without repeated attempts before rate limiting', () => {
  const probes = abuseProbeReportProbes();
  probes[0].attempts = 1;

  assert.throws(
    () => recordEvidence(
      { release_candidate: 'abc123', items: [{ id: 'ABUSE-LIMIT-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes,
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe -api-base=https://api.staging.scriptureforge.ai',
    ),
    /auth-rate-limit must prove repeated attempts before HTTP 429/,
  );
});

test('recordEvidence rejects abuse evidence without structured scoped-profile proof', () => {
  for (const { probeName, field, message } of [
    { probeName: 'auth-account-rate-limit', field: 'account_scoped', message: /auth-account-rate-limit must prove account_scoped=true/ },
    { probeName: 'auth-account-rate-limit', field: 'forwarded_client_ip_rotated', message: /auth-account-rate-limit must prove forwarded_client_ip_rotated=true/ },
    { probeName: 'auth-refresh-rate-limit', field: 'refresh_token_scoped', message: /auth-refresh-rate-limit must prove refresh_token_scoped=true/ },
    { probeName: 'websocket-rate-limit', field: 'websocket_upgrade', message: /websocket-rate-limit must prove websocket_upgrade=true/ },
  ]) {
    const probes = abuseProbeReportProbes((name) => (
      name === probeName ? { [field]: false } : {}
    ));

    assert.throws(
      () => recordEvidence(
        { release_candidate: 'abc123', items: [{ id: 'ABUSE-LIMIT-001', status: 'pending_external' }] },
        {
          observed_at: '2026-06-25T12:00:00Z',
          api_target: 'https://api.staging.scriptureforge.ai',
          web_origin: 'https://app.staging.scriptureforge.ai',
          config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
          config_artifact_verified: true,
          config_artifact_summary: abuseConfigSummary,
          threshold_pass: true,
          release_candidate: 'abc123',
          service_version: 'scriptureforge-api:abc123',
          evidence_items: ['ABUSE-LIMIT-001'],
          probes,
        },
        'artifacts/abuseprobe.json',
        'go run ./tools/abuseprobe -api-base=https://api.staging.scriptureforge.ai',
      ),
      message,
    );
  }
});

test('recordEvidence rejects weak abuse evidence', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'http://127.0.0.1:8080',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: [
          {
            name: 'auth-rate-limit',
            passed: true,
            status_code: 429,
            attempts: 2,
            retry_after: '60',
            rate_limit: '1',
          },
        ],
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /must use HTTPS api_target/,
  );
});

test('recordEvidence rejects HTTPS loopback abuse evidence', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://localhost:8443',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /api_target must not be local\/self-test/,
  );
});

test('recordEvidence rejects abuse evidence without staging config artifact', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /must include HTTPS config_artifact_url/,
  );
});

test('recordEvidence rejects abuse evidence without verified config artifact markers', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes(),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /ABUSE-LIMIT-001 report must prove config_artifact_verified=true/,
  );
});

test('recordEvidence rejects abuse evidence without verified marker summaries', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.scriptureforge.ai',
        web_origin: 'https://app.staging.scriptureforge.ai',
        config_artifact_url: 'https://artifacts.staging.scriptureforge.ai/abuse/config.txt',
        config_artifact_verified: true,
        config_artifact_summary: abuseConfigSummary,
        threshold_pass: true,
        release_candidate: 'abc123',
        service_version: 'scriptureforge-api:abc123',
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: abuseProbeReportProbes((name) => ({
          result_summary: name === 'websocket-rate-limit'
            ? 'got 429 with headers after 2 attempts; verified markers: websocket-rate-limit, staging artifact, 429, after, attempts, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset'
            : abuseProbeMarkerSummaries[name],
        })),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /websocket-rate-limit result_summary must include verified marker repeated_attempts_verified=true/,
  );
});

test('recordEvidence rejects Redis sequencing evidence without WebSocket load evidence', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-REDIS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DATA-REDIS-001'],
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest',
    ),
    /DATA-REDIS-001 load evidence must be paired with PERF-WS-001/,
  );
});

test('recordManualEvidence marks one explicit manifest item as passed', () => {
  const manifest = {
    schema_version: 1,
    environment: 'staging',
    release_candidate: 'abc123',
    generated_at: '2026-06-25T00:00:00Z',
    items: [
      {
        id: 'SEC-SIGNOFF-001',
        category: 'security',
        status: 'pending_external',
        description: 'Owner/security signoff',
        required_evidence: ['release signoff'],
      },
      {
        id: 'DR-BACKUP-001',
        category: 'resilience',
        status: 'pending_external',
        description: 'Backup proof',
        required_evidence: ['backup'],
      },
    ],
  };

  const updated = recordManualEvidence(
    manifest,
    'SEC-SIGNOFF-001',
    'artifacts/release-signoff.txt',
    'security review signoff',
    'threat model approval complete; security/dependency_risk_register.md#DRR-001 dependency risk decision reviewed; residual risk review complete; owner/security approval recorded; release risk signoff approved; release_candidate=abc123',
    '2026-06-25T13:00:00Z',
  );

  const signoff = updated.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  const backup = updated.items.find((item) => item.id === 'DR-BACKUP-001');
  assert.equal(signoff.status, 'passed');
  assert.equal(signoff.evidence.length, 1);
  assert.match(signoff.evidence[0].result_summary, /threat model approval/);
  assert.equal(backup.status, 'pending_external');
});

test('recordManualEvidence rejects security signoff summaries without exact release candidate', () => {
  assert.throws(
    () => recordManualEvidence(
      {
        release_candidate: 'abc123',
        items: [{ id: 'SEC-SIGNOFF-001', status: 'pending_external' }],
      },
      'SEC-SIGNOFF-001',
      'artifacts/release-signoff.txt',
      'security review signoff',
      'threat model approval complete; security/dependency_risk_register.md#DRR-001 dependency risk decision reviewed; residual risk review complete; owner/security approval recorded; release risk signoff approved; release_candidate=oldsha',
      '2026-06-25T13:00:00Z',
    ),
    /SEC-SIGNOFF-001 result_summary must include verified marker release_candidate=abc123/,
  );
});

test('recordManualEvidence rejects weak security signoff summaries', () => {
  assert.throws(
    () => recordManualEvidence(
      { release_candidate: 'abc123', items: [{ id: 'SEC-SIGNOFF-001', status: 'pending_external' }] },
      'SEC-SIGNOFF-001',
      'artifacts/release-signoff.txt',
      'security review signoff',
      'owner and security approved release',
      '2026-06-25T13:00:00Z',
    ),
    /SEC-SIGNOFF-001 result_summary must include verified marker threat model approval/,
  );
});

test('recordManualEvidence rejects probe-backed production evidence items', () => {
  assert.throws(
    () => recordManualEvidence(
      { items: [{ id: 'DEPLOY-TF-001', status: 'pending_external' }] },
      'DEPLOY-TF-001',
      'artifacts/terraform-plan.txt',
      'terraform plan',
      'manual terraform summary',
      '2026-06-25T13:00:00Z',
    ),
    /DEPLOY-TF-001 must be recorded from its dedicated probe report/,
  );
  assert.throws(
    () => recordManualEvidence(
      { items: [{ id: 'CLIENT-WEB-001', status: 'pending_external' }] },
      'CLIENT-WEB-001',
      'artifacts/web-smoke.txt',
      'browser smoke',
      'manual web smoke summary',
      '2026-06-25T13:00:00Z',
    ),
    /CLIENT-WEB-001 must be recorded from its dedicated probe report/,
  );
  assert.throws(
    () => recordManualEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      'PERF-HTTP-001',
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
      'manual load summary',
      '2026-06-25T13:00:00Z',
    ),
    /PERF-HTTP-001 must be recorded from its dedicated probe report/,
  );
});

test('recordManualEvidence rejects invalid timestamps and unknown items', () => {
  assert.throws(
    () => recordManualEvidence({ items: [] }, 'SEC-SIGNOFF-001', 'artifact', 'command', 'summary', 'today'),
    /observedAt must be ISO UTC/,
  );
  assert.throws(
    () => recordManualEvidence({ items: [] }, 'SEC-SIGNOFF-001', 'artifact', 'command', 'summary', '2026-06-25T13:00:00Z'),
    /manifest missing evidence item/,
  );
});

test('recordStatus records blocked and failed entries with owner and blocker', () => {
  const manifest = {
    items: [
      { id: 'DEPLOY-TF-001', status: 'pending_external', evidence: [{ artifact: 'old' }] },
      { id: 'DR-BACKUP-001', status: 'pending_external' },
    ],
  };

  recordStatus(manifest, 'DEPLOY-TF-001', 'blocked', {
    owner: 'platform',
    blocker: 'waiting on AWS staging account access',
  });
  recordStatus(manifest, 'DR-BACKUP-001', 'failed', {
    owner: 'database',
    blocker: 'restore drill failed checksum verification',
  });

  const terraform = manifest.items.find((item) => item.id === 'DEPLOY-TF-001');
  const backup = manifest.items.find((item) => item.id === 'DR-BACKUP-001');
  assert.equal(terraform.status, 'blocked');
  assert.equal(terraform.owner, 'platform');
  assert.equal(terraform.blocker, 'waiting on AWS staging account access');
  assert.equal(terraform.evidence, undefined);
  assert.equal(backup.status, 'failed');
  assert.equal(backup.owner, 'database');
});

test('recordStatus records accepted risk decisions', () => {
  const manifest = {
    items: [
      { id: 'SEC-SIGNOFF-001', status: 'pending_external', owner: 'security', blocker: 'old blocker' },
    ],
  };

  recordStatus(manifest, 'SEC-SIGNOFF-001', 'accepted_risk', {
    decisionRef: 'security/dependency_risk_register.md#DRR-001',
    owner: 'security',
    acceptedBy: 'release-owner',
    reviewDueAt: '2026-07-25',
    expiresAt: '2026-08-25',
  });

  const item = manifest.items[0];
  assert.equal(item.status, 'accepted_risk');
  assert.equal(item.decision_ref, 'security/dependency_risk_register.md#DRR-001');
  assert.equal(item.owner, 'security');
  assert.equal(item.accepted_by, 'release-owner');
  assert.equal(item.review_due_at, '2026-07-25');
  assert.equal(item.expires_at, '2026-08-25');
  assert.equal(item.blocker, undefined);
});

test('recordStatus rejects incomplete status details', () => {
  assert.throws(
    () => recordStatus({ items: [{ id: 'DEPLOY-TF-001' }] }, 'DEPLOY-TF-001', 'blocked', { owner: 'platform' }),
    /requires blocker/,
  );
  assert.throws(
    () => recordStatus({ items: [{ id: 'SEC-SIGNOFF-001' }] }, 'SEC-SIGNOFF-001', 'accepted_risk', {}),
    /requires decisionRef/,
  );
  assert.throws(
    () => recordStatus(
      { items: [{ id: 'SEC-SIGNOFF-001' }] },
      'SEC-SIGNOFF-001',
      'accepted_risk',
      {
        decisionRef: 'security/dependency_risk_register.md#DRR-001',
        owner: 'security',
        acceptedBy: 'release-owner',
        reviewDueAt: '2026-07-25',
      },
    ),
    /requires expiresAt/,
  );
  assert.throws(
    () => recordStatus(
      { items: [{ id: 'SEC-SIGNOFF-001' }] },
      'SEC-SIGNOFF-001',
      'accepted_risk',
      {
        decisionRef: 'security/dependency_risk_register.md#DRR-001',
        owner: 'security',
        acceptedBy: 'release-owner',
        reviewDueAt: '2026-09-01',
        expiresAt: '2026-08-25',
      },
    ),
    /requires reviewDueAt on or before expiresAt/,
  );
  assert.throws(
    () => recordStatus(
      { items: [{ id: 'SEC-SIGNOFF-001' }] },
      'SEC-SIGNOFF-001',
      'accepted_risk',
      {
        decisionRef: 'security/dependency_risk_register.md#DRR-001',
        owner: 'security',
        acceptedBy: 'release-owner',
        reviewDueAt: '2026-07-25',
        expiresAt: '2026-08-25',
        currentDate: '2026-07-26',
      },
    ),
    /requires reviewDueAt that is not already overdue/,
  );
  assert.throws(
    () => recordStatus(
      { items: [{ id: 'SEC-SIGNOFF-001' }] },
      'SEC-SIGNOFF-001',
      'accepted_risk',
      {
        decisionRef: 'security/dependency_risk_register.md#DRR-001',
        owner: 'security',
        acceptedBy: 'release-owner',
        reviewDueAt: '2026-01-01',
        expiresAt: '2026-01-02',
      },
    ),
    /requires expiresAt that is not already expired/,
  );
  assert.throws(
    () => recordStatus(
      { items: [{ id: 'SEC-SIGNOFF-001' }] },
      'SEC-SIGNOFF-001',
      'accepted_risk',
      {
        decisionRef: 'security/dependency_risk_register.md#DRR-001',
        owner: 'security',
        acceptedBy: 'release-owner',
        reviewDueAt: '2026-06-25',
        expiresAt: '2026-06-26',
        currentDate: '2026-06-27',
      },
    ),
    /requires expiresAt that is not already expired/,
  );
  assert.throws(
    () => recordStatus(
      { items: [{ id: 'SEC-SIGNOFF-001' }] },
      'SEC-SIGNOFF-001',
      'accepted_risk',
      {
        decisionRef: 'security/dependency_risk_register.md#DRR-001',
        owner: 'security',
        acceptedBy: 'release-owner',
        reviewDueAt: '2026-06-25',
        expiresAt: '2026-06-26',
        currentDate: 'today',
      },
    ),
    /requires currentDate as YYYY-MM-DD/,
  );
});
