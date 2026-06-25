import assert from 'node:assert/strict';
import test from 'node:test';

import { parseArgs, recordEvidence, recordManualEvidence, recordStatus, summarizeProbeReport } from './record-staging-evidence.mjs';

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
    dns_artifact_url: 'https://artifacts.staging.example/tls/dns.txt',
    acm_artifact_url: 'https://artifacts.staging.example/tls/acm.txt',
    web_target: 'https://app.staging.example',
    web_auth_smoke_url: 'https://artifacts.staging.example/web/auth-smoke.txt',
    web_journal_smoke_url: 'https://artifacts.staging.example/web/journal-smoke.txt',
    web_room_smoke_url: 'https://artifacts.staging.example/web/room-smoke.txt',
    probes: [
      { name: 'api-tls', passed: true },
      { name: 'web-root', passed: true },
    ],
  };

  const updated = recordEvidence(manifest, report, 'artifacts/stagingprobe.json', 'go run ./tools/stagingprobe');

  for (const item of updated.items) {
    assert.equal(item.status, 'passed');
    assert.equal(item.evidence.length, 1);
    assert.equal(item.evidence[0].artifact, 'artifacts/stagingprobe.json');
    assert.equal(item.evidence[0].command_or_probe, 'go run ./tools/stagingprobe');
    assert.match(item.evidence[0].result_summary, /2 probes passed/);
  }
});

test('recordEvidence records production-grade CI release evidence', () => {
  const manifest = {
    items: [{ id: 'SRC-CI-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      commit_sha: '0123456789abcdef0123456789abcdef01234567',
      workflow_name: 'Security Pipeline Verification',
      ci_run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
      evidence_items: ['SRC-CI-001'],
      probes: [
        {
          name: 'github-actions-release-run',
          passed: true,
          target: 'artifacts/ci-release-evidence.txt',
          run_url: 'https://github.com/example/scriptureforgeai/actions/runs/1234567890',
        },
      ],
    },
    'artifacts/ciprobe.json',
    'go run ./tools/ciprobe -run-artifact-file artifacts/ci-release-evidence.txt',
  );

  assert.equal(updated.items[0].status, 'passed');
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
        evidence_items: ['SRC-CI-001'],
        probes: [{ name: 'github-actions-release-run', passed: true }],
      },
      'artifacts/ciprobe.json',
      'go run ./tools/ciprobe',
    ),
    /must include GitHub Actions ci_run_url/,
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
        web_target: 'https://app.staging.example',
        probes: [{ name: 'web-root', passed: true }],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /must include HTTPS web_auth_smoke_url/,
  );
});

test('recordEvidence records production-grade tenant RLS evidence', () => {
  const manifest = {
    items: [{ id: 'DATA-RLS-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      api_target: 'https://api.staging.example',
      evidence_items: ['DATA-RLS-001'],
      probes: [
        { name: 'owner-create-encrypted-journal', passed: true, target: 'https://api.staging.example/api/v1/journal_entries', status_code: 201 },
        { name: 'owner-read-created-journal', passed: true, target: 'https://api.staging.example/api/v1/journal_entries/entry-1', status_code: 200 },
        { name: 'blocked-read-created-journal', passed: true, target: 'https://api.staging.example/api/v1/journal_entries/entry-1', status_code: 404 },
        { name: 'blocked-list-excludes-created-journal', passed: true, target: 'https://api.staging.example/api/v1/journal_entries', status_code: 200 },
        {
          name: 'database-rls-context-proof',
          passed: true,
          target: 'https://artifacts.staging.example/data/rls-db-proof.txt',
          status_code: 200,
        },
      ],
    },
    'artifacts/tenantprobe.json',
    'go run ./tools/tenantprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects tenant RLS evidence without deployed API and DB proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DATA-RLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        api_target: 'http://localhost:8080',
        evidence_items: ['DATA-RLS-001'],
        probes: [
          { name: 'owner-create-encrypted-journal', passed: true },
          { name: 'owner-read-created-journal', passed: true },
          { name: 'blocked-read-created-journal', passed: true },
          { name: 'blocked-list-excludes-created-journal', passed: true },
          { name: 'database-rls-context-proof', passed: true, target: 'http://localhost/rls.txt', status_code: 200 },
        ],
      },
      'artifacts/tenantprobe.json',
      'go run ./tools/tenantprobe',
    ),
    /must use HTTPS api_target/,
  );
});

test('recordEvidence records production-grade mobile evidence', () => {
  const manifest = {
    items: [{ id: 'CLIENT-MOBILE-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      evidence_items: ['CLIENT-MOBILE-001'],
      probes: [
        {
          name: 'mobile-eas-or-device-run',
          passed: true,
          target: 'https://artifacts.staging.example/mobile/eas-build.txt',
          status_code: 200,
        },
        {
          name: 'mobile-native-crypto-smoke',
          passed: true,
          target: 'https://artifacts.staging.example/mobile/native-crypto-smoke.txt',
          status_code: 200,
        },
        {
          name: 'mobile-staging-config',
          passed: true,
          target: 'https://artifacts.staging.example/mobile/staging-config.txt',
          status_code: 200,
        },
      ],
    },
    'artifacts/mobileprobe.json',
    'go run ./tools/mobileprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects mobile evidence without native HTTPS artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'CLIENT-MOBILE-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['CLIENT-MOBILE-001'],
        probes: [
          { name: 'mobile-eas-or-device-run', passed: true, target: 'https://artifacts.staging.example/mobile/eas-build.txt', status_code: 200 },
          { name: 'mobile-native-crypto-smoke', passed: true, target: 'http://localhost/native-crypto.txt', status_code: 200 },
          { name: 'mobile-staging-config', passed: true, target: 'https://artifacts.staging.example/mobile/staging-config.txt', status_code: 200 },
        ],
      },
      'artifacts/mobileprobe.json',
      'go run ./tools/mobileprobe',
    ),
    /mobile-native-crypto-smoke target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence records production-grade Rust gRPC evidence', () => {
  const manifest = {
    items: [{ id: 'RUST-GRPC-001', status: 'pending_external' }],
  };

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
      metrics_target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
      evidence_items: ['RUST-GRPC-001'],
      probes: [
        {
          name: 'rust-grpc-health',
          passed: true,
          target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
          status: 'SERVING',
        },
        {
          name: 'rust-metrics',
          passed: true,
          target: 'http://scriptureforge-rust-engine.staging.svc.cluster.local:9102/metrics',
          status_code: 200,
        },
      ],
    },
    'artifacts/rustprobe.json',
    'go run ./tools/rustprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects Rust gRPC evidence without metrics proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'RUST-GRPC-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
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

test('recordEvidence records production-grade Zoom evidence', () => {
  const manifest = {
    items: [{ id: 'EXT-ZOOM-001', status: 'pending_external' }],
  };

  const probeNames = [
    'zoom-oauth-readiness',
    'zoom-meeting-create-or-fallback',
    'zoom-timeout-circuit-fallback',
    'zoom-webhook-signature-delivery',
    'zoom-duplicate-webhook-idempotency',
    'zoom-meeting-room-mapping',
  ];

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      threshold_pass: true,
      evidence_items: ['EXT-ZOOM-001'],
      probes: probeNames.map((name) => ({
        name,
        passed: true,
        target: `https://artifacts.staging.example/zoom/${name}.txt`,
        status_code: 200,
      })),
    },
    'artifacts/zoomprobe.json',
    'go run ./tools/zoomprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects Zoom evidence without HTTPS artifact proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'EXT-ZOOM-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['EXT-ZOOM-001'],
        probes: [
          { name: 'zoom-oauth-readiness', passed: true, target: 'https://artifacts.staging.example/zoom/oauth.txt', status_code: 200 },
          { name: 'zoom-meeting-create-or-fallback', passed: true, target: 'https://artifacts.staging.example/zoom/meeting.txt', status_code: 200 },
          { name: 'zoom-timeout-circuit-fallback', passed: true, target: 'http://localhost/zoom/resilience.txt', status_code: 200 },
          { name: 'zoom-webhook-signature-delivery', passed: true, target: 'https://artifacts.staging.example/zoom/webhook.txt', status_code: 200 },
          { name: 'zoom-duplicate-webhook-idempotency', passed: true, target: 'https://artifacts.staging.example/zoom/duplicate.txt', status_code: 200 },
          { name: 'zoom-meeting-room-mapping', passed: true, target: 'https://artifacts.staging.example/zoom/mapping.txt', status_code: 200 },
        ],
      },
      'artifacts/zoomprobe.json',
      'go run ./tools/zoomprobe',
    ),
    /zoom-timeout-circuit-fallback target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence records production-grade AI evidence', () => {
  const manifest = {
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
      evidence_items: ['EXT-AI-001'],
      probes: probeNames.map((name) => ({
        name,
        passed: true,
        target: `https://artifacts.staging.example/ai/${name}.txt`,
        status_code: 200,
      })),
    },
    'artifacts/aiprobe.json',
    'go run ./tools/aiprobe',
  );

  assert.equal(updated.items[0].status, 'passed');
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
          { name: 'ai-provider-config', passed: true, target: 'https://artifacts.staging.example/ai/provider.txt', status_code: 200 },
          { name: 'ai-generation-route', passed: true, target: 'https://artifacts.staging.example/ai/generation.txt', status_code: 200 },
          { name: 'ai-timeout-degradation', passed: true, target: 'http://localhost/ai/degradation.txt', status_code: 200 },
          { name: 'ai-citation-verification', passed: true, target: 'https://artifacts.staging.example/ai/citation.txt', status_code: 200 },
          { name: 'ai-audit-persistence', passed: true, target: 'https://artifacts.staging.example/ai/audit.txt', status_code: 200 },
        ],
      },
      'artifacts/aiprobe.json',
      'go run ./tools/aiprobe',
    ),
    /ai-timeout-degradation target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence rejects TLS evidence without DNS and ACM artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-TLS-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-TLS-001'],
        probes: [{ name: 'api-tls', passed: true }],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /must include HTTPS dns_artifact_url/,
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
          target: 'https://artifacts.staging.example/deploy/terraform-init.txt',
          status_code: 200,
        },
        {
          name: 'terraform-staging-plan',
          passed: true,
          target: 'https://artifacts.staging.example/deploy/terraform-plan.txt',
          status_code: 200,
        },
        {
          name: 'terraform-staging-apply-or-approval',
          passed: true,
          target: 'https://artifacts.staging.example/deploy/terraform-apply-or-approval.txt',
          status_code: 200,
        },
      ],
    },
    'artifacts/deploymentprobe-terraform.json',
    'go run ./tools/deploymentprobe -probe-terraform',
  );

  assert.equal(updated.items[0].status, 'passed');
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
          { name: 'terraform-remote-backend-init', passed: true, target: 'https://artifacts.staging.example/deploy/terraform-init.txt', status_code: 200 },
          { name: 'terraform-staging-plan', passed: true, target: 'http://localhost/deploy/terraform-plan.txt', status_code: 200 },
          { name: 'terraform-staging-apply-or-approval', passed: true, target: 'https://artifacts.staging.example/deploy/terraform-apply.txt', status_code: 200 },
        ],
      },
      'artifacts/deploymentprobe-terraform.json',
      'go run ./tools/deploymentprobe -probe-terraform',
    ),
    /terraform-staging-plan target must be an HTTPS artifact URL/,
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
          target: 'https://artifacts.staging.example/deploy/kubectl-rollout-status.txt',
        },
        {
          name: 'kubernetes-workload-resources',
          passed: true,
          target: 'https://artifacts.staging.example/deploy/kubectl-resources.txt',
        },
      ],
    },
    'artifacts/deploymentprobe-k8s.json',
    'go run ./tools/deploymentprobe -probe-kubernetes',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects Kubernetes evidence without rollout and resource artifact probes', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'DEPLOY-K8S-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['DEPLOY-K8S-001'],
        probes: [{ name: 'api-ready', passed: true, target: 'https://api.staging.example/ready' }],
      },
      'artifacts/stagingprobe.json',
      'go run ./tools/stagingprobe',
    ),
    /must include kubernetes-rollout-status probe/,
  );
});

test('recordEvidence records production-grade observability evidence', () => {
  const manifest = {
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
      evidence_items: ['OBS-OTEL-001', 'OBS-ALERT-001'],
      probes: probeNames.map((name) => ({
        name,
        passed: true,
        target: `https://observability.staging.example/${name}`,
        status_code: 200,
      })),
    },
    'artifacts/observabilityprobe.json',
    'go run ./tools/observabilityprobe -probe-otel -probe-alerts',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
});

test('recordEvidence rejects observability evidence from local telemetry surfaces', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'OBS-OTEL-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['OBS-OTEL-001'],
        probes: [
          { name: 'collector-otlp-config', passed: true, target: 'https://observability.staging.example/collector', status_code: 200 },
          { name: 'api-prometheus-metrics', passed: true, target: 'https://api.staging.example/metrics', status_code: 200 },
          { name: 'rust-prometheus-metrics', passed: true, target: 'http://127.0.0.1:9102/metrics', status_code: 200 },
          { name: 'trace-backend-search', passed: true, target: 'https://traces.staging.example/search', status_code: 200 },
          { name: 'log-backend-trace-correlation', passed: true, target: 'https://logs.staging.example/search', status_code: 200 },
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
      evidence_items: ['SEC-SECRETS-001', 'SEC-DBUSER-001'],
      probes: [
        ...artifactProbeNames.map((name) => ({
          name,
          passed: true,
          target: `https://artifacts.staging.example/security/${name}.txt`,
          status_code: 200,
        })),
        {
          name: 'database-scoped-user',
          passed: true,
          target: 'redacted-database-url',
          result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false createrole=false createdb=false',
        },
      ],
    },
    'artifacts/securityprobe.json',
    'go run ./tools/securityprobe -probe-secrets -probe-db-user',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
});

test('recordEvidence rejects security evidence with local secret artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-SECRETS-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['SEC-SECRETS-001'],
        probes: [
          { name: 'irsa-service-account', passed: true, target: 'https://artifacts.staging.example/security/service-account.txt', status_code: 200 },
          { name: 'secret-provider-class', passed: true, target: 'https://artifacts.staging.example/security/secret-provider.txt', status_code: 200 },
          { name: 'synced-secret-metadata-redacted', passed: true, target: 'http://localhost/security/synced-secret.txt', status_code: 200 },
          { name: 'iam-secrets-policy', passed: true, target: 'https://artifacts.staging.example/security/iam.txt', status_code: 200 },
          { name: 'scoped-secrets-access-test', passed: true, target: 'https://artifacts.staging.example/security/access-test.txt', status_code: 200 },
        ],
      },
      'artifacts/securityprobe.json',
      'go run ./tools/securityprobe -probe-secrets',
    ),
    /synced-secret-metadata-redacted target must be an HTTPS artifact URL/,
  );
});

test('recordEvidence rejects database user evidence without non-admin role proof', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'SEC-DBUSER-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['SEC-DBUSER-001'],
        probes: [
          {
            name: 'database-scoped-user',
            passed: true,
            target: 'redacted-database-url',
            result_summary: 'connected as "scriptureforge_app" in 25ms; superuser=false createrole=false',
          },
        ],
      },
      'artifacts/securityprobe-db.json',
      'go run ./tools/securityprobe -probe-db-user',
    ),
    /database-scoped-user summary must prove createdb=false/,
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
        target: 'https://api.staging.example/health',
        min_rps: 100,
        max_p99_ms: 200,
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
      target: 'https://api.staging.example/health',
      min_rps: 5000,
      max_p99_ms: 200,
      rps: 5200,
      p99_ms: 180,
      http_replica_artifact_url: 'https://artifacts.staging.example/load/http-replicas.txt',
      dependency_telemetry_artifact_url: 'https://artifacts.staging.example/load/dependency-telemetry.txt',
    },
    'artifacts/load-http.json',
    'go run ./tools/loadtest -target=https://api.staging.example/health -min-rps=5000 -max-p99=200ms',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects HTTP performance evidence without staging telemetry artifacts', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'PERF-HTTP-001', status: 'pending_external' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        threshold_pass: true,
        evidence_items: ['PERF-HTTP-001'],
        target: 'https://api.staging.example/health',
        min_rps: 5000,
        max_p99_ms: 200,
        rps: 5200,
        p99_ms: 180,
      },
      'artifacts/load-http.json',
      'go run ./tools/loadtest',
    ),
    /must include HTTPS http_replica_artifact_url/,
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
      target: 'wss://api.staging.example/api/v1/rooms/stream/room-1',
      min_rps: 500,
      max_p99_ms: 200,
      rps: 620,
      p99_ms: 140,
      ws_replica_artifact_url: 'https://artifacts.staging.example/load/ws-replicas.txt',
      redis_telemetry_artifact_url: 'https://artifacts.staging.example/load/redis-telemetry.txt',
    },
    'artifacts/load-ws.json',
    'go run ./tools/loadtest -websocket -target=wss://api.staging.example/api/v1/rooms/stream/room-1',
  );

  assert.equal(updated.items[0].status, 'passed');
  assert.equal(updated.items[1].status, 'passed');
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
        target: 'wss://api.staging.example/api/v1/rooms/stream/room-1',
        min_rps: 500,
        max_p99_ms: 200,
        rps: 620,
        p99_ms: 140,
      },
      'artifacts/load-ws.json',
      'go run ./tools/loadtest -websocket',
    ),
    /must include HTTPS ws_replica_artifact_url/,
  );
});

test('recordEvidence records production-grade abuse evidence', () => {
  const manifest = {
    items: [{ id: 'ABUSE-LIMIT-001', status: 'pending_external' }],
  };

  const probes = ['auth-rate-limit', 'ai-rate-limit', 'journal-rate-limit', 'rooms-rate-limit', 'websocket-rate-limit']
    .map((name) => ({
      name,
      passed: true,
      status_code: 429,
      retry_after: '60',
      rate_limit: '1',
      rate_limit_remaining: '0',
      rate_limit_reset: '1782403200',
    }));

  const updated = recordEvidence(
    manifest,
    {
      observed_at: '2026-06-25T12:00:00Z',
      api_target: 'https://api.staging.example',
      config_artifact_url: 'https://artifacts.staging.example/abuse/config.txt',
      threshold_pass: true,
      evidence_items: ['ABUSE-LIMIT-001'],
      probes,
    },
    'artifacts/abuseprobe.json',
    'go run ./tools/abuseprobe -api-base=https://api.staging.example',
  );

  assert.equal(updated.items[0].status, 'passed');
});

test('recordEvidence rejects weak abuse evidence', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'http://127.0.0.1:8080',
        config_artifact_url: 'https://artifacts.staging.example/abuse/config.txt',
        threshold_pass: true,
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: [
          {
            name: 'auth-rate-limit',
            passed: true,
            status_code: 429,
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

test('recordEvidence rejects abuse evidence without staging config artifact', () => {
  assert.throws(
    () => recordEvidence(
      { items: [{ id: 'ABUSE-LIMIT-001' }] },
      {
        observed_at: '2026-06-25T12:00:00Z',
        api_target: 'https://api.staging.example',
        threshold_pass: true,
        evidence_items: ['ABUSE-LIMIT-001'],
        probes: ['auth-rate-limit', 'ai-rate-limit', 'journal-rate-limit', 'rooms-rate-limit', 'websocket-rate-limit']
          .map((name) => ({
            name,
            passed: true,
            status_code: 429,
            retry_after: '60',
            rate_limit: '1',
            rate_limit_remaining: '0',
            rate_limit_reset: '1782403200',
          })),
      },
      'artifacts/abuseprobe.json',
      'go run ./tools/abuseprobe',
    ),
    /must include HTTPS config_artifact_url/,
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
    'owner and security approved release risk record',
    '2026-06-25T13:00:00Z',
  );

  const signoff = updated.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  const backup = updated.items.find((item) => item.id === 'DR-BACKUP-001');
  assert.equal(signoff.status, 'passed');
  assert.equal(signoff.evidence.length, 1);
  assert.equal(signoff.evidence[0].result_summary, 'owner and security approved release risk record');
  assert.equal(backup.status, 'pending_external');
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
  });

  const item = manifest.items[0];
  assert.equal(item.status, 'accepted_risk');
  assert.equal(item.decision_ref, 'security/dependency_risk_register.md#DRR-001');
  assert.equal(item.owner, undefined);
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
});
