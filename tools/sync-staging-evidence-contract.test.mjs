import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parseArgs, syncPendingRequiredEvidence } from './sync-staging-evidence-contract.mjs';
import { requiredIds } from './validate-staging-evidence.mjs';

function item(id, status, requiredEvidence, extra = {}) {
  return {
    id,
    category: extra.category ?? 'deployment',
    status,
    description: extra.description ?? `${id} description`,
    required_evidence: requiredEvidence,
    ...extra,
  };
}

function manifest(items) {
  const itemById = new Map(items.map((currentItem) => [currentItem.id, currentItem]));
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    generated_at: '2026-06-28T00:00:00Z',
    items: requiredIds.map((id) => itemById.get(id) ?? item(id, 'pending_external', defaultRequiredEvidence(id))),
  };
}

function defaultRequiredEvidence(id) {
  if (id === 'SEC-SIGNOFF-001') {
    return [
      'Owner/security approval record captured as a content-verified repo security/*.md signoff/approval document or HTTPS non-local approval artifact',
      'signoff_artifact_verified=true',
    ];
  }
  return [`${id} proof`];
}

test('parseArgs accepts manifest and contract paths', () => {
  assert.deepEqual(
    parseArgs([
      '--manifest',
      'staging.json',
      '--contract-manifest',
      'example.json',
      '--check',
    ]),
    {
      manifest: 'staging.json',
      contractManifest: 'example.json',
      check: true,
      apply: false,
    },
  );
});

test('syncPendingRequiredEvidence refreshes pending external checklist drift', () => {
  const current = manifest([
    item('DEPLOY-TF-001', 'pending_external', ['old plan proof'], {
      artifact_url: 'https://example.com/staging/deploy-tf.json',
    }),
  ]);
  const contract = manifest([
    item('DEPLOY-TF-001', 'pending_external', ['new plan proof', 'new apply proof']),
  ]);

  const result = syncPendingRequiredEvidence(current, contract);

  assert.deepEqual(result.changed, [{
    id: 'DEPLOY-TF-001',
    previous_count: 1,
    next_count: 2,
  }]);
  const updatedItem = result.manifest.items.find((currentItem) => currentItem.id === 'DEPLOY-TF-001');
  assert.deepEqual(updatedItem.required_evidence, ['new plan proof', 'new apply proof']);
  assert.equal(updatedItem.artifact_url, 'https://example.com/staging/deploy-tf.json');
});

test('syncPendingRequiredEvidence preserves non-pending evidence items', () => {
  const current = manifest([
    item('SRC-CI-001', 'blocked', ['old proof'], {
      blocker: 'waiting on exact release CI run',
      owner: 'release-owner',
    }),
  ]);
  const contract = manifest([
    item('SRC-CI-001', 'pending_external', ['new proof']),
  ]);

  const result = syncPendingRequiredEvidence(current, contract);

  assert.equal(result.changed_count, 0);
  const preservedItem = result.manifest.items.find((currentItem) => currentItem.id === 'SRC-CI-001');
  assert.deepEqual(preservedItem.required_evidence, ['old proof']);
  assert.equal(preservedItem.status, 'blocked');
  assert.equal(preservedItem.blocker, 'waiting on exact release CI run');
  assert.equal(preservedItem.owner, 'release-owner');
});

test('checked-in deployment contract names failure contradiction exclusions', () => {
  const contract = JSON.parse(readFileSync('production-readiness/staging-evidence.example.json', 'utf8'));
  for (const id of ['DEPLOY-TF-001', 'DEPLOY-K8S-001']) {
    const deploymentItem = contract.items.find((candidate) => candidate.id === id);
    assert.ok(deploymentItem, `${id} must exist in staging evidence contract`);
    const checklist = deploymentItem.required_evidence.join('\n');
    assert.match(checklist, /Terraform init\/plan\/apply failure/, `${id} contract must reject Terraform failure contradictions`);
    assert.match(checklist, /rollout failure/, `${id} contract must reject rollout failure contradictions`);
    assert.match(checklist, /zero ready\/available replica/, `${id} contract must reject zero-replica contradictions`);
    assert.match(checklist, /CrashLoopBackOff/, `${id} contract must reject crash-loop contradictions`);
    assert.match(checklist, /ImagePullBackOff/, `${id} contract must reject image-pull contradictions`);
  }
});

test('checked-in external-service contract names contradiction exclusions', () => {
  const contract = JSON.parse(readFileSync('production-readiness/staging-evidence.example.json', 'utf8'));
  const zoomItem = contract.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  assert.ok(zoomItem, 'EXT-ZOOM-001 must exist in staging evidence contract');
  const zoomChecklist = zoomItem.required_evidence.join('\n');
  assert.match(zoomChecklist, /signature verification disabled/, 'Zoom contract must reject disabled signature verification contradictions');
  assert.match(zoomChecklist, /signature verification bypassed/, 'Zoom contract must reject bypassed signature verification contradictions');
  assert.match(zoomChecklist, /skip signature verification/, 'Zoom contract must reject skipped signature verification contradictions');

  const aiItem = contract.items.find((candidate) => candidate.id === 'EXT-AI-001');
  assert.ok(aiItem, 'EXT-AI-001 must exist in staging evidence contract');
  const aiChecklist = aiItem.required_evidence.join('\n');
  assert.match(aiChecklist, /citation verification disabled/, 'AI contract must reject disabled citation verification contradictions');
  assert.match(aiChecklist, /audit logging disabled/, 'AI contract must reject disabled audit logging contradictions');
  assert.match(aiChecklist, /ai_request_logs disabled/, 'AI contract must reject disabled AI audit persistence contradictions');
  assert.match(aiChecklist, /citation_trails disabled/, 'AI contract must reject disabled citation trail contradictions');
});

test('checked-in security contract names strict secret leak exclusions', () => {
  const contract = JSON.parse(readFileSync('production-readiness/staging-evidence.example.json', 'utf8'));
  const securityItem = contract.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  assert.ok(securityItem, 'SEC-SECRETS-001 must exist in staging evidence contract');
  const checklist = securityItem.required_evidence.join('\n');
  assert.match(checklist, /postgres:\/\//, 'Security contract must reject plaintext Postgres DSN markers');
  assert.match(checklist, /postgresql:\/\//, 'Security contract must reject plaintext PostgreSQL DSN markers');
  assert.match(checklist, /sk-/, 'Security contract must reject OpenAI-style API key markers');
  assert.match(checklist, /client_secret:/, 'Security contract must reject client secret markers');
  assert.match(checklist, /webhook_secret:/, 'Security contract must reject webhook secret markers');
  assert.match(checklist, /password:/, 'Security contract must reject password markers');
  assert.match(checklist, /stringData/, 'Security contract must reject Kubernetes stringData fields');
  assert.match(checklist, /-----BEGIN/, 'Security contract must reject PEM private key markers');
});

test('checked-in performance contract names threshold contradiction exclusions', () => {
  const contract = JSON.parse(readFileSync('production-readiness/staging-evidence.example.json', 'utf8'));
  for (const id of ['PERF-HTTP-001', 'PERF-WS-001']) {
    const performanceItem = contract.items.find((candidate) => candidate.id === id);
    assert.ok(performanceItem, `${id} must exist in staging evidence contract`);
    const checklist = performanceItem.required_evidence.join('\n');
    assert.match(checklist, /threshold failed/, `${id} contract must reject threshold failure contradictions`);
    assert.match(checklist, /threshold_failures/, `${id} contract must reject structured threshold failure contradictions`);
    assert.match(checklist, /RPS below threshold/, `${id} contract must reject RPS-below-threshold contradictions`);
    assert.match(checklist, /P99 above threshold/, `${id} contract must reject P99-above-threshold contradictions`);
  }
});

test('checked-in resilience contract names failed drill exclusions', () => {
  const contract = JSON.parse(readFileSync('production-readiness/staging-evidence.example.json', 'utf8'));
  for (const id of ['DR-ROLLBACK-001', 'DR-BACKUP-001']) {
    const resilienceItem = contract.items.find((candidate) => candidate.id === id);
    assert.ok(resilienceItem, `${id} must exist in staging evidence contract`);
    const checklist = resilienceItem.required_evidence.join('\n');
    assert.match(checklist, /rollback failed/, `${id} contract must reject failed rollback contradictions`);
    assert.match(checklist, /rollout undo failed/, `${id} contract must reject failed rollout undo contradictions`);
    assert.match(checklist, /degradation drill failed/, `${id} contract must reject failed degradation drill contradictions`);
    assert.match(checklist, /backup failed/, `${id} contract must reject failed backup contradictions`);
    assert.match(checklist, /restore failed/, `${id} contract must reject failed restore contradictions`);
    assert.match(checklist, /smoke failed/, `${id} contract must reject failed smoke contradictions`);
    assert.match(checklist, /RPO exceeded/, `${id} contract must reject RPO breach contradictions`);
    assert.match(checklist, /RTO exceeded/, `${id} contract must reject RTO breach contradictions`);
  }
});
