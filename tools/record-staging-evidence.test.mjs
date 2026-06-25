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

test('recordManualEvidence marks one explicit manifest item as passed', () => {
  const manifest = {
    schema_version: 1,
    environment: 'staging',
    release_candidate: 'abc123',
    generated_at: '2026-06-25T00:00:00Z',
    items: [
      {
        id: 'DEPLOY-TF-001',
        category: 'deployment',
        status: 'pending_external',
        description: 'Terraform proof',
        required_evidence: ['plan'],
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
    'DEPLOY-TF-001',
    'artifacts/terraform-plan.txt',
    'terraform plan -var-file=terraform.tfvars',
    'remote backend initialized and staging plan produced no destructive changes',
    '2026-06-25T13:00:00Z',
  );

  const terraform = updated.items.find((item) => item.id === 'DEPLOY-TF-001');
  const backup = updated.items.find((item) => item.id === 'DR-BACKUP-001');
  assert.equal(terraform.status, 'passed');
  assert.equal(terraform.evidence.length, 1);
  assert.equal(terraform.evidence[0].result_summary, 'remote backend initialized and staging plan produced no destructive changes');
  assert.equal(backup.status, 'pending_external');
});

test('recordManualEvidence rejects invalid timestamps and unknown items', () => {
  assert.throws(
    () => recordManualEvidence({ items: [] }, 'DEPLOY-TF-001', 'artifact', 'command', 'summary', 'today'),
    /observedAt must be ISO UTC/,
  );
  assert.throws(
    () => recordManualEvidence({ items: [] }, 'DEPLOY-TF-001', 'artifact', 'command', 'summary', '2026-06-25T13:00:00Z'),
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
