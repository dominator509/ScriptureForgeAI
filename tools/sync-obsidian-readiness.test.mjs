import { readFile, rm, writeFile } from 'node:fs/promises';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { parseArgs, syncObsidianReadiness } from './sync-obsidian-readiness.mjs';
import { requiredIds } from './validate-staging-evidence.mjs';

const snapshotStartMarker = '<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-START -->';
const snapshotEndMarker = '<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-END -->';

test('parseArgs accepts manifest/note/check/apply flags', () => {
  const args = parseArgs(['--manifest', 'staging.json', '--note', 'note.md', '--check', '--apply']);
  assert.equal(args.manifest, 'staging.json');
  assert.equal(args.contractManifest, 'production-readiness/staging-evidence.example.json');
  assert.equal(args.note, 'note.md');
  assert.equal(args.check, true);
  assert.equal(args.apply, true);
});

test('parseArgs accepts contract manifest flag', () => {
  const args = parseArgs(['--manifest', 'staging.json', '--contract-manifest', 'example.json', '--note', 'note.md']);
  assert.equal(args.manifest, 'staging.json');
  assert.equal(args.contractManifest, 'example.json');
  assert.equal(args.note, 'note.md');
});

test('syncObsidianReadiness writes snapshot when apply is true', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'sf-obsidian-readiness-'));
  const manifestPath = join(workspace, 'staging.json');
  const notePath = join(workspace, 'obsidian.md');

  await writeFile(
    manifestPath,
    JSON.stringify(buildManifest({
      statusFor: () => 'passed',
    })),
    'utf8',
  );
  await writeFile(notePath, '# sample', 'utf8');

  const firstResult = await syncObsidianReadiness({
    manifestPath,
    notePath,
    check: false,
    apply: true,
    pathReportBuilder: readyPathReportBuilder,
  });

  const noteAfterWrite = await readFile(notePath, 'utf8');
  assert.equal(firstResult.updated, true);
  assert.equal(firstResult.changed, true);
  assert.match(noteAfterWrite, new RegExp(snapshotStartMarker));
  assert.match(noteAfterWrite, new RegExp(snapshotEndMarker));

  const secondResult = await syncObsidianReadiness({
    manifestPath,
    notePath,
    check: true,
    apply: false,
    pathReportBuilder: readyPathReportBuilder,
  });
  assert.equal(secondResult.updated, false);

  await rm(workspace, { recursive: true, force: true });
});

test('syncObsidianReadiness check rejects stale snapshot content', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'sf-obsidian-readiness-'));
  const manifestPath = join(workspace, 'staging.json');
  const notePath = join(workspace, 'obsidian.md');

  await writeFile(
    manifestPath,
    JSON.stringify(buildManifest({
      statusFor: () => 'passed',
    }), null, 2),
    'utf8',
  );
  await writeFile(
    notePath,
    [
      '# sample',
      snapshotStartMarker,
      '## Staging Evidence Snapshot (staging)',
      'line mismatch',
      snapshotEndMarker,
    ].join('\n'),
    'utf8',
  );

  await assert.rejects(
    async () => syncObsidianReadiness({
      manifestPath,
      notePath,
      check: true,
      apply: false,
      pathReportBuilder: readyPathReportBuilder,
    }),
    /stale/i,
  );

  await rm(workspace, { recursive: true, force: true });
});

test('syncObsidianReadiness snapshot includes strict staging PATH blockers', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'sf-obsidian-readiness-'));
  const manifestPath = join(workspace, 'staging.json');
  const notePath = join(workspace, 'obsidian.md');

  await writeFile(
    manifestPath,
    JSON.stringify(buildManifest({
      statusFor: () => 'passed',
    }), null, 2),
    'utf8',
  );
  await writeFile(notePath, '# sample', 'utf8');

  await syncObsidianReadiness({
    manifestPath,
    notePath,
    apply: true,
    pathReportBuilder: missingStrictPathReportBuilder,
  });

  const noteAfterWrite = await readFile(notePath, 'utf8');
  assert.match(noteAfterWrite, /strict_staging_path_ready: no/);
  assert.match(noteAfterWrite, /STAGING-PATH-TOOLS/);
  assert.match(noteAfterWrite, /psql on PATH \(install PostgreSQL client\)/);
  assert.match(noteAfterWrite, /aws on PATH \(install AWS CLI v2\)/);

  await rm(workspace, { recursive: true, force: true });
});

test('syncObsidianReadiness snapshot includes pending contract drift blockers', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'sf-obsidian-readiness-'));
  const manifestPath = join(workspace, 'staging.json');
  const contractPath = join(workspace, 'example.json');
  const notePath = join(workspace, 'obsidian.md');
  const manifest = buildManifest({
    items: [
      {
        id: 'OBS-OTEL-001',
        category: 'observability',
        status: 'pending_external',
        description: 'OTEL proof',
        required_evidence: ['old checklist'],
      },
      ...requiredIds.filter((id) => id !== 'OBS-OTEL-001').map((id) => ({
        id,
        category: 'category',
        status: 'passed',
        description: `${id} proof`,
      })),
    ],
  });
  const contract = buildManifest({
    items: [
      {
        id: 'OBS-OTEL-001',
        category: 'observability',
        status: 'pending_external',
        description: 'OTEL proof',
        required_evidence: ['new checklist', 'release marker checklist'],
      },
      ...requiredIds.filter((id) => id !== 'OBS-OTEL-001').map((id) => ({
        id,
        category: 'category',
        status: 'passed',
        description: `${id} proof`,
      })),
    ],
  });

  await writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');
  await writeFile(contractPath, JSON.stringify(contract, null, 2), 'utf8');
  await writeFile(notePath, '# sample', 'utf8');

  await syncObsidianReadiness({
    manifestPath,
    contractManifestPath: contractPath,
    notePath,
    apply: true,
    pathReportBuilder: readyPathReportBuilder,
  });

  const noteAfterWrite = await readFile(notePath, 'utf8');
  assert.match(noteAfterWrite, /STAGING-EVIDENCE-CONTRACT/);
  assert.match(noteAfterWrite, /OBS-OTEL-001 required_evidence must be refreshed/);

  await rm(workspace, { recursive: true, force: true });
});

test('syncObsidianReadiness snapshot includes expected release candidate mismatches', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'sf-obsidian-readiness-'));
  const manifestPath = join(workspace, 'staging.json');
  const notePath = join(workspace, 'obsidian.md');

  await writeFile(
    manifestPath,
    JSON.stringify(buildManifest({
      statusFor: () => 'passed',
    }), null, 2),
    'utf8',
  );
  await writeFile(notePath, '# sample', 'utf8');

  await syncObsidianReadiness({
    manifestPath,
    notePath,
    expectedReleaseCandidate: 'fedcba9876543210fedcba9876543210fedcba98',
    apply: true,
    pathReportBuilder: readyPathReportBuilder,
  });

  const noteAfterWrite = await readFile(notePath, 'utf8');
  assert.match(noteAfterWrite, /release_candidate_matches_expected: no/);
  assert.match(noteAfterWrite, /non_manifest_blockers: 1/);
  assert.match(noteAfterWrite, /RELEASE-CANDIDATE-SHA/);

  await rm(workspace, { recursive: true, force: true });
});

function buildManifest({
  statusFor,
  items = [],
}) {
  const statusForItem = statusFor ?? (() => 'passed');
  const manifestItems = items.length > 0 ? items : requiredIds.map((id) => ({
    id,
    category: 'category',
    status: statusForItem(id),
    description: `${id} proof`,
  }));
  for (const item of manifestItems) {
    if (item.status === 'pending_external') {
      item.required_evidence ??= ['artifact'];
    } else if (item.status === 'passed') {
      item.evidence = [{
        observed_at: '2026-06-26T00:00:00Z',
        command_or_probe: 'probe',
        artifact: `artifacts/${item.id}.json`,
        result_summary: 'passed',
      }];
    } else if (item.status === 'accepted_risk' && item.id !== 'SEC-SIGNOFF-001') {
      item.decision_ref = `security/decision.md#${item.id}`;
    }
  }
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: '0123456789abcdef0123456789abcdef01234567',
    generated_at: '2026-06-26T00:00:00Z',
    items: manifestItems,
  };
}

function readyPathReportBuilder({ strictStaging } = {}) {
  return pathReport({
    mode: strictStaging ? 'staging-evidence' : 'local',
    missing: new Set(),
  });
}

function missingStrictPathReportBuilder({ strictStaging } = {}) {
  return pathReport({
    mode: strictStaging ? 'staging-evidence' : 'local',
    missing: new Set(['psql', 'aws']),
  });
}

function pathReport({ mode, missing }) {
  const required = ['rtk', 'git', 'go', 'node', 'npm', 'cargo', 'rustc', 'terraform'].map((name) => ({
    name,
    required: true,
    ok: !missing.has(name),
  }));
  const optional = [
    { name: 'gopls' },
    { name: 'psql', remediation: 'install PostgreSQL client' },
    { name: 'kubectl' },
    { name: 'aws', remediation: 'install AWS CLI v2' },
    { name: 'gh' },
  ].map((command) => ({
    ...command,
    required: true,
    strict: true,
    ok: !missing.has(command.name),
  }));
  return {
    schema_version: 1,
    mode,
    threshold_pass: [...required, ...optional].every((command) => command.ok),
    required,
    optional,
  };
}
