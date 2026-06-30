import assert from 'node:assert/strict';
import test from 'node:test';
import {
  formatObsidian,
  formatText,
  parseArgs,
  stagingEvidenceGapReportProofMarkers,
  summarizeGaps,
} from './report-staging-evidence-gaps.mjs';
import { requiredIds } from './validate-staging-evidence.mjs';

test('parseArgs supports manifest and output format', () => {
  const args = parseArgs([
    '--manifest',
    'staging.json',
    '--contract-manifest',
    'example.json',
    '--format',
    'json',
    '--expected-release-candidate',
    'abcdef0123456789abcdef0123456789abcdef01',
    '--allow-blockers',
  ]);
  assert.equal(args.manifest, 'staging.json');
  assert.equal(args.contractManifest, 'example.json');
  assert.equal(args.format, 'json');
  assert.equal(args.expectedReleaseCandidate, 'abcdef0123456789abcdef0123456789abcdef01');
  assert.equal(args.allowBlockers, true);
});

test('summarizeGaps reports pending required-evidence contract drift', () => {
  const manifest = baseManifest({
    statusFor: () => 'passed',
  });
  const contract = baseManifest({
    statusFor: () => 'passed',
  });
  const stale = manifest.items.find((item) => item.id === 'OBS-OTEL-001');
  const current = contract.items.find((item) => item.id === 'OBS-OTEL-001');
  stale.status = 'pending_external';
  stale.required_evidence = ['old observability checklist'];
  delete stale.evidence;
  current.status = 'pending_external';
  current.required_evidence = ['new observability checklist', 'release_candidate marker'];
  delete current.evidence;

  const summary = summarizeGaps(manifest, { contractManifest: contract });

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.non_manifest_blockers, 1);
  const blocker = summary.blocking_items.find((item) => item.id === 'STAGING-EVIDENCE-CONTRACT');
  assert.ok(blocker);
  assert.deepEqual(blocker.drift_items, ['OBS-OTEL-001']);
  assert.match(formatText(summary), /STAGING-EVIDENCE-CONTRACT/);
  assert.match(formatText(summary), /OBS-OTEL-001 required_evidence must be refreshed/);
  assert.match(formatObsidian(summary), /STAGING-EVIDENCE-CONTRACT/);
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
  assert.deepEqual(summary.proof_markers, stagingEvidenceGapReportProofMarkers);
});

test('summarizeGaps allows accepted risk only for security signoff', () => {
  const manifest = baseManifest({
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });

  const summary = summarizeGaps(manifest, { today: '2026-06-29' });

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.accepted_risk, 1);
  assert.equal(summary.blocking_items.length, 1);
  assert.equal(summary.blocking_items[0].id, 'STAGING-EVIDENCE-STRICT-VALIDATION');
  assert.match(summary.blocking_items[0].required_evidence[0], /SRC-CI-001 strict release evidence must include a tools\/ciprobe JSON report/);
});

test('summarizeGaps reports strict validation blockers for weak passed evidence', () => {
  const manifest = baseManifest({
    statusFor: () => 'passed',
  });

  const summary = summarizeGaps(manifest);

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.non_manifest_blockers, 1);
  assert.equal(summary.blocking_items.length, 1);
  assert.equal(summary.blocking_items[0].id, 'STAGING-EVIDENCE-STRICT-VALIDATION');
  assert.match(summary.blocking_items[0].required_evidence[0], /strict release evidence must include/);
  assert.match(formatText(summary), /STAGING-EVIDENCE-STRICT-VALIDATION/);
  assert.match(formatObsidian(summary), /STAGING-EVIDENCE-STRICT-VALIDATION/);
});

test('summarizeGaps rejects overdue signoff accepted risk instead of hiding it', () => {
  const manifest = baseManifest({
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });

  assert.throws(
    () => summarizeGaps(manifest, { today: '2026-07-26' }),
    /SEC-SIGNOFF-001 accepted risk review_due_at must not be before validation date/,
  );
});

test('summarizeGaps rejects security signoff accepted risk for the wrong decision record', () => {
  const manifest = baseManifest({
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const signoff = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoff.decision_ref = 'security/decision.md#DRR-999';

  const summary = summarizeGaps(manifest);

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.accepted_risk, 1);
  assert.equal(summary.blocking_items.length, 1);
  assert.equal(summary.blocking_items[0].id, 'SEC-SIGNOFF-001');
  assert.equal(summary.blocking_items[0].decision_ref, 'security/decision.md#DRR-999');
  assert.match(formatText(summary), /SEC-SIGNOFF-001/);
  assert.match(formatText(summary), /decision_ref: security\/decision\.md#DRR-999/);
});

test('summarizeGaps treats non-signoff accepted risk as strict release blocker', () => {
  const manifest = baseManifest({
    statusFor: (id) => id === 'DEPLOY-TF-001' ? 'accepted_risk' : 'passed',
  });

  const summary = summarizeGaps(manifest);

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.blocking_items[0].id, 'DEPLOY-TF-001');
  assert.equal(summary.blocking_items[0].decision_ref, 'security/decision.md#DEPLOY-TF-001');
  assert.equal(summary.blocking_items[0].owner, 'release-owner');
  assert.equal(summary.blocking_items[0].accepted_by, 'security-lead');
  assert.equal(summary.blocking_items[0].review_due_at, '2026-07-25');
  assert.equal(summary.blocking_items[0].expires_at, '2026-08-25');
});

test('formatText prints counts and evidence checklist', () => {
  const summary = summarizeGaps(baseManifest({
    statusFor: (id) => id === 'CLIENT-MOBILE-001' ? 'pending_external' : 'passed',
  }));

  const text = formatText(summary);

  assert.match(text, /strict release ready: no/);
  for (const marker of stagingEvidenceGapReportProofMarkers) {
    assert.match(text, new RegExp(marker));
  }
  assert.match(text, /CLIENT-MOBILE-001/);
  assert.match(text, /required: artifact for CLIENT-MOBILE-001/);
  assert.match(text, /blocking_item_required_evidence_listed=true/);
  assert.match(text, /gap report proof footer: strict_release_ready=no/);
  assert.match(text, /blocking_items=1/);
  assert.match(text, /blocking_item_ids=CLIENT-MOBILE-001/);
  assert.match(text, /counts=passed:\d+\|pending_external:1\|blocked:0\|failed:0\|accepted_risk:0\|non_manifest:0/);
});

test('formatObsidian prints blocking-item evidence for Obsidian', () => {
  const summary = summarizeGaps(baseManifest({
    statusFor: (id) => id === 'ABUSE-LIMIT-001' ? 'blocked' : 'passed',
  }));
  summary.blocking_items[0].owner = 'security-team';
  summary.blocking_items[0].blocker = 'load test credentials missing';

  const text = formatObsidian(summary);

  assert.match(text, /## Staging Evidence Snapshot/);
  for (const marker of stagingEvidenceGapReportProofMarkers) {
    assert.match(text, new RegExp(marker));
  }
  assert.match(text, /ABUSE-LIMIT-001/);
  assert.match(text, /owner: security-team/);
  assert.match(text, /blocker: load test credentials missing/);
  assert.match(text, /blocking_item_required_evidence_listed=true/);
});

test('formatText and formatObsidian include accepted-risk ownership details', () => {
  const summary = summarizeGaps(baseManifest({
    statusFor: (id) => id === 'DEPLOY-TF-001' ? 'accepted_risk' : 'passed',
  }));

  const text = formatText(summary);
  const obsidian = formatObsidian(summary);

  for (const output of [text, obsidian]) {
    assert.match(output, /decision_ref: security\/decision\.md#DEPLOY-TF-001/);
    assert.match(output, /owner: release-owner/);
    assert.match(output, /accepted_by: security-lead/);
    assert.match(output, /review_due_at: 2026-07-25/);
    assert.match(output, /expires_at: 2026-08-25/);
  }
});

test('summarizeGaps treats stale release candidate as release blocker', () => {
  const manifest = baseManifest({
    statusFor: () => 'passed',
  });

  const summary = summarizeGaps(manifest, {
    expectedReleaseCandidate: 'fedcba9876543210fedcba9876543210fedcba98',
  });

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.non_manifest_blockers, 1);
  assert.equal(summary.release_candidate_matches_expected, false);
  assert.equal(summary.blocking_items[0].id, 'RELEASE-CANDIDATE-SHA');
  assert.equal(summary.blocking_items[0].actual_release_candidate, manifest.release_candidate);
  assert.equal(summary.blocking_items[0].expected_release_candidate, 'fedcba9876543210fedcba9876543210fedcba98');
  assert.match(formatText(summary), /expected release candidate: fedcba9876543210fedcba9876543210fedcba98 \(mismatch\)/);
  assert.match(formatText(summary), /non-manifest blockers: 1/);
});

test('summarizeGaps reports strict staging PATH blockers', () => {
  const summary = summarizeGaps(baseManifest({
    statusFor: () => 'passed',
  }), {
    strictPathReport: strictPathReport({ missing: ['psql', 'aws'], broken: ['gh'] }),
  });

  assert.equal(summary.strict_release_ready, false);
  assert.equal(summary.strict_staging_path_ready, false);
  assert.equal(summary.failed, 0);
  assert.equal(summary.non_manifest_blockers, 1);
  const pathBlocker = summary.blocking_items.find((item) => item.id === 'STAGING-PATH-TOOLS');
  assert.ok(pathBlocker);
  assert.equal(pathBlocker.status, 'failed');
  assert.deepEqual(pathBlocker.required_evidence, [
    'psql on PATH (install PostgreSQL client)',
    'aws on PATH (install AWS CLI v2)',
    'gh on PATH with a successful version check (currently resolves but version check failed: <version check failed: gh broken version shim>)',
  ]);
  assert.deepEqual(pathBlocker.searched_paths, [
    {
      name: 'psql',
      paths: ['C:\\Program Files\\PostgreSQL\\17\\bin', 'C:\\Users\\domin\\scoop\\shims'],
    },
    {
      name: 'aws',
      paths: ['C:\\Program Files\\Amazon\\AWSCLIV2', 'C:\\Users\\domin\\AppData\\Local\\Microsoft\\WinGet\\Links'],
    },
  ]);
  assert.match(formatText(summary), /strict staging PATH ready: no/);
  assert.match(formatText(summary), /non-manifest blockers: 1/);
  assert.match(formatText(summary), /STAGING-PATH-TOOLS/);
  assert.match(formatText(summary), /searched psql:/);
  assert.match(formatText(summary), /C:\\Program Files\\PostgreSQL\\17\\bin/);
  assert.match(formatText(summary), /searched aws:/);
  assert.match(formatText(summary), /C:\\Users\\domin\\AppData\\Local\\Microsoft\\WinGet\\Links/);
  assert.match(formatObsidian(summary), /strict_staging_path_ready: no/);
  assert.match(formatObsidian(summary), /non_manifest_blockers: 1/);
  assert.match(formatObsidian(summary), /aws on PATH/);
  assert.match(formatObsidian(summary), /gh on PATH with a successful version check/);
  assert.match(formatObsidian(summary), /searched psql:/);
  assert.match(formatObsidian(summary), /C:\\Users\\domin\\scoop\\shims/);
});

test('summarizeGaps counts release SHA and PATH blockers separately from manifest statuses', () => {
  const summary = summarizeGaps(baseManifest({
    statusFor: () => 'passed',
  }), {
    expectedReleaseCandidate: 'fedcba9876543210fedcba9876543210fedcba98',
    strictPathReport: strictPathReport({ missing: ['psql', 'aws'] }),
  });

  assert.equal(summary.failed, 0);
  assert.equal(summary.pending_external, 0);
  assert.equal(summary.non_manifest_blockers, 2);
  assert.deepEqual(
    summary.blocking_items.map((item) => item.id),
    ['RELEASE-CANDIDATE-SHA', 'STAGING-PATH-TOOLS'],
  );
  assert.match(formatText(summary), /non-manifest blockers: 2/);
  assert.match(formatObsidian(summary), /non_manifest_blockers: 2/);
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

function strictPathReport({ missing, broken = [] }) {
  const missingSet = new Set(missing);
  const brokenSet = new Set(broken);
  const required = ['rtk', 'git', 'go', 'node', 'npm', 'cargo', 'rustc', 'terraform'].map((name) => ({
    name,
    required: true,
    ok: !missingSet.has(name),
  }));
  const optional = [
    { name: 'gopls', remediation: undefined },
    { name: 'psql', remediation: 'install PostgreSQL client', searched_paths: ['C:\\Program Files\\PostgreSQL\\17\\bin', 'C:\\Users\\domin\\scoop\\shims'] },
    { name: 'kubectl', remediation: undefined },
    { name: 'aws', remediation: 'install AWS CLI v2', searched_paths: ['C:\\Program Files\\Amazon\\AWSCLIV2', 'C:\\Users\\domin\\AppData\\Local\\Microsoft\\WinGet\\Links'] },
    { name: 'gh', remediation: undefined },
  ].map((command) => ({
    ...command,
    required: true,
    strict: true,
    ok: !missingSet.has(command.name) && !brokenSet.has(command.name),
    paths: missingSet.has(command.name) ? [] : [`C:\\tools\\${command.name}.exe`],
    version: brokenSet.has(command.name) ? `<version check failed: ${command.name} broken version shim>` : `${command.name} test-version`,
    version_ok: brokenSet.has(command.name) ? false : !missingSet.has(command.name) ? true : null,
  }));
  return {
    schema_version: 1,
    mode: 'staging-evidence',
    threshold_pass: [...required, ...optional].every((command) => command.ok),
    required,
    optional,
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
    item.decision_ref = id === 'SEC-SIGNOFF-001'
      ? 'security/dependency_risk_register.md#DRR-001'
      : `security/decision.md#${id}`;
    item.owner = 'release-owner';
    item.accepted_by = 'security-lead';
    item.review_due_at = '2026-07-25';
    item.expires_at = '2026-08-25';
  }

  return item;
}
