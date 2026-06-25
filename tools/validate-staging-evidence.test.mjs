import assert from 'node:assert/strict';
import test from 'node:test';
import { parseArgs, requiredIds, validateManifest } from './validate-staging-evidence.mjs';

test('parseArgs supports manifest path and strict release mode', () => {
  const args = parseArgs(['--manifest', 'production-readiness/staging.json', '--strict-release']);
  assert.equal(args.evidenceFile, 'production-readiness/staging.json');
  assert.equal(args.strictRelease, true);
});

test('validateManifest accepts pending items in contract mode', () => {
  const manifest = baseManifest({
    statusFor: () => 'pending_external',
  });

  const result = validateManifest(manifest);

  assert.equal(result.items, requiredIds.length);
  assert.equal(result.strictRelease, false);
});

test('validateManifest strict release accepts passed items and signoff accepted risk', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });

  assert.doesNotThrow(() => validateManifest(manifest, { strictRelease: true }));
});

test('validateManifest strict release rejects pending, blocked, and failed items', () => {
  for (const status of ['pending_external', 'blocked', 'failed']) {
    const manifest = baseManifest({
      releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
      statusFor: (id) => id === 'DEPLOY-TF-001' ? status : 'passed',
    });

    assert.throws(
      () => validateManifest(manifest, { strictRelease: true }),
      /DEPLOY-TF-001 must be passed/,
    );
  }
});

test('validateManifest strict release rejects accepted risk outside signoff item', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'DEPLOY-TF-001' ? 'accepted_risk' : 'passed',
  });

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 must be passed/,
  );
});

test('validateManifest strict release rejects placeholder release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: 'replace-with-git-sha-or-tag',
    statusFor: () => 'passed',
  });

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /real release_candidate/,
  );
});

function baseManifest({ releaseCandidate = 'replace-with-git-sha-or-tag', statusFor }) {
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: releaseCandidate,
    generated_at: '2026-06-25T00:00:00Z',
    items: requiredIds.map((id) => buildItem(id, statusFor(id))),
  };
}

function buildItem(id, status) {
  const item = {
    id,
    category: 'test',
    status,
    description: `${id} proof`,
  };

  if (status === 'pending_external') {
    item.required_evidence = ['artifact'];
  } else if (status === 'passed') {
    item.evidence = [
      {
        observed_at: '2026-06-25T12:00:00Z',
        command_or_probe: 'probe',
        artifact: `artifacts/${id}.json`,
        result_summary: 'passed',
      },
    ];
  } else if (status === 'blocked' || status === 'failed') {
    item.owner = 'platform';
    item.blocker = `${status} in test`;
  } else if (status === 'accepted_risk') {
    item.decision_ref = `security/dependency_risk_register.md#${id}`;
  }

  return item;
}
