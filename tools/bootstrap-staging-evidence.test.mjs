import assert from 'node:assert/strict';
import test from 'node:test';
import { requiredIds } from './validate-staging-evidence.mjs';
import { bootstrapManifest, parseArgs } from './bootstrap-staging-evidence.mjs';

test('parseArgs supports template, output, environment, release candidate, and force', () => {
  const args = parseArgs([
    '--template',
    'contract.json',
    '--out',
    'staging.json',
    '--environment',
    'preprod',
    '--release-candidate',
    'abc123',
    '--force',
  ]);

  assert.equal(args.template, 'contract.json');
  assert.equal(args.out, 'staging.json');
  assert.equal(args.environment, 'preprod');
  assert.equal(args.releaseCandidate, 'abc123');
  assert.equal(args.force, true);
});

test('bootstrapManifest stamps release metadata and resets items to pending evidence', () => {
  const template = {
    schema_version: 1,
    environment: 'example',
    release_candidate: 'replace-with-git-sha-or-tag',
    generated_at: '2026-06-25T00:00:00Z',
    items: requiredIds.map((id) => ({
      id,
      category: 'category',
      status: 'passed',
      description: `${id} proof`,
      required_evidence: ['real artifact'],
      evidence: [{ artifact: 'old.json' }],
      owner: 'old owner',
      blocker: 'old blocker',
      decision_ref: 'old decision',
    })),
  };

  const manifest = bootstrapManifest(template, {
    environment: 'staging',
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    generatedAt: '2026-06-25T16:00:00Z',
  });

  assert.equal(manifest.environment, 'staging');
  assert.equal(manifest.release_candidate, '0123456789abcdef0123456789abcdef01234567');
  assert.equal(manifest.generated_at, '2026-06-25T16:00:00Z');
  assert.equal(manifest.items.length, requiredIds.length);
  for (const item of manifest.items) {
    assert.equal(item.status, 'pending_external');
    assert.deepEqual(item.required_evidence, ['real artifact']);
    assert.equal(item.evidence, undefined);
    assert.equal(item.owner, undefined);
    assert.equal(item.blocker, undefined);
    assert.equal(item.decision_ref, undefined);
  }
});

test('bootstrapManifest rejects templates without pending evidence requirements', () => {
  assert.throws(
    () => bootstrapManifest(
      {
        schema_version: 1,
        environment: 'example',
        release_candidate: 'replace-with',
        generated_at: '2026-06-25T00:00:00Z',
        items: [{ id: 'SRC-CI-001', category: 'ci', status: 'passed', description: 'ci' }],
      },
      {
        environment: 'staging',
        releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
        generatedAt: '2026-06-25T16:00:00Z',
      },
    ),
    /template item must include required_evidence/,
  );
});
