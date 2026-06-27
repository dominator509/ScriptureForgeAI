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
  assert.equal(args.note, 'note.md');
  assert.equal(args.check, true);
  assert.equal(args.apply, true);
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
    }),
    /stale/i,
  );

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
      item.required_evidence = ['artifact'];
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
