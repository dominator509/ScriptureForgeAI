import assert from 'node:assert/strict';
import test from 'node:test';
import {
  formatObsidian,
  formatText,
  parseArgs,
  summarizeGaps,
} from './report-staging-evidence-gaps.mjs';
import { requiredIds } from './validate-staging-evidence.mjs';

test('parseArgs supports manifest and output format', () => {
  const args = parseArgs([
    '--manifest',
    'staging.json',
    '--format',
    'json',
    '--expected-release-candidate',
    'abcdef0123456789abcdef0123456789abcdef01',
  ]);
  assert.equal(args.manifest, 'staging.json');
  assert.equal(args.format, 'json');
  assert.equal(args.expectedReleaseCandidate, 'abcdef0123456789abcdef0123456789abcdef01');
});

test('summarizeGaps reports pending release blockers with required evidence', () => {
  const manifest = baseManifest({
    statusFor: (id) => id === 'SRC-CI-001' ? 'pending_external' : 'passed',
  });

  const summary = summarizeGaps(manifest);

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.passed, requiredIds.length - 1);
  assert.equal(summary.pending_external, 1);
  assert.equal(summary.blocking_items.length, 1);
  assert.equal(summary.blocking_items[0].id, 'SRC-CI-001');
  assert.deepEqual(summary.blocking_items[0].required_evidence, ['artifact for SRC-CI-001']);
});

test('summarizeGaps allows accepted risk only for security signoff', () => {
  const manifest = baseManifest({
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });

  const summary = summarizeGaps(manifest);

  assert.equal(summary.strict_release_ready, true);
  assert.equal(summary.accepted_risk, 1);
  assert.deepEqual(summary.blocking_items, []);
});

test('summarizeGaps treats non-signoff accepted risk as strict release blocker', () => {
  const manifest = baseManifest({
    statusFor: (id) => id === 'DEPLOY-TF-001' ? 'accepted_risk' : 'passed',
  });

  const summary = summarizeGaps(manifest);

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.blocking_items[0].id, 'DEPLOY-TF-001');
  assert.equal(summary.blocking_items[0].decision_ref, 'security/decision.md#DEPLOY-TF-001');
});

test('formatText prints counts and evidence checklist', () => {
  const summary = summarizeGaps(baseManifest({
    statusFor: (id) => id === 'CLIENT-MOBILE-001' ? 'pending_external' : 'passed',
  }));

  const text = formatText(summary);

  assert.match(text, /strict release ready: no/);
  assert.match(text, /CLIENT-MOBILE-001/);
  assert.match(text, /required: artifact for CLIENT-MOBILE-001/);
});

test('formatObsidian prints blocking-item evidence for Obsidian', () => {
  const summary = summarizeGaps(baseManifest({
    statusFor: (id) => id === 'ABUSE-LIMIT-001' ? 'blocked' : 'passed',
  }));
  summary.blocking_items[0].owner = 'security-team';
  summary.blocking_items[0].blocker = 'load test credentials missing';

  const text = formatObsidian(summary);

  assert.match(text, /## Staging Evidence Snapshot/);
  assert.match(text, /ABUSE-LIMIT-001/);
  assert.match(text, /owner: security-team/);
  assert.match(text, /blocker: load test credentials missing/);
});

test('summarizeGaps treats stale release candidate as release blocker', () => {
  const manifest = baseManifest({
    statusFor: () => 'passed',
  });

  const summary = summarizeGaps(manifest, {
    expectedReleaseCandidate: 'fedcba9876543210fedcba9876543210fedcba98',
  });

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.release_candidate_matches_expected, false);
  assert.equal(summary.blocking_items[0].id, 'RELEASE-CANDIDATE-SHA');
  assert.equal(summary.blocking_items[0].actual_release_candidate, manifest.release_candidate);
  assert.equal(summary.blocking_items[0].expected_release_candidate, 'fedcba9876543210fedcba9876543210fedcba98');
  assert.match(formatText(summary), /expected release candidate: fedcba9876543210fedcba9876543210fedcba98 \(mismatch\)/);
});

function baseManifest({ statusFor }) {
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: '0123456789abcdef0123456789abcdef01234567',
    generated_at: '2026-06-25T16:00:00Z',
    items: requiredIds.map((id) => buildItem(id, statusFor(id))),
  };
}

function buildItem(id, status) {
  const item = {
    id,
    category: 'category',
    status,
    description: `${id} proof`,
  };

  if (status === 'pending_external') {
    item.required_evidence = [`artifact for ${id}`];
  } else if (status === 'blocked') {
    item.owner = 'security-team';
    item.blocker = `blocker for ${id}`;
  } else if (status === 'passed') {
    item.evidence = [
      {
        observed_at: '2026-06-25T16:00:00Z',
        command_or_probe: 'probe',
        artifact: `artifacts/${id}.json`,
        result_summary: 'passed',
      },
    ];
  } else if (status === 'accepted_risk') {
    item.decision_ref = `security/decision.md#${id}`;
  }

  return item;
}
