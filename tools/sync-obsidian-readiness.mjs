import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { formatObsidian, summarizeGaps } from './report-staging-evidence-gaps.mjs';
import { validateManifest } from './validate-staging-evidence.mjs';
import { buildPathReport } from './verify-project-path.mjs';

const snapshotStartMarker = '<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-START -->';
const snapshotEndMarker = '<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-END -->';

export const obsidianReadinessProofMarkers = [
  'manifest_validated=true',
  'gap_summary_rendered=true',
  'snapshot_markers_present=true',
  'strict_staging_path_status_rendered=true',
  'contract_drift_status_rendered=true',
  'release_candidate_match_status_rendered=true',
  'snapshot_body_current=true',
];

export function parseArgs(argv) {
  const args = {
    manifest: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.staging.json',
    contractManifest: process.env.STAGING_EVIDENCE_CONTRACT_FILE ?? 'production-readiness/staging-evidence.example.json',
    note: 'production-readiness/obsidian-production-readiness.md',
    check: false,
    apply: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--manifest') {
      args.manifest = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--contract-manifest') {
      args.contractManifest = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--note') {
      args.note = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--check') {
      args.check = true;
    } else if (argv[i] === '--apply') {
      args.apply = true;
    } else if (argv[i] === '--expected-release-candidate') {
      args.expectedReleaseCandidate = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }

  assert.ok(args.manifest, '--manifest must not be empty');
  assert.ok(args.contractManifest, '--contract-manifest must not be empty');
  assert.ok(args.note, '--note must not be empty');
  return args;
}

function readJSON(pathname) {
  return readFile(pathname, 'utf8').then((content) => JSON.parse(content.replace(/^\uFEFF/, '')));
}

function formatSnapshot(summary) {
  return [
    snapshotStartMarker,
    ...formatObsidian(summary).split('\n'),
    snapshotEndMarker,
    '',
  ].join('\n').trimEnd();
}

function extractEmbeddedSnapshot(noteText) {
  const escapedStart = escapeRegExp(snapshotStartMarker);
  const escapedEnd = escapeRegExp(snapshotEndMarker);
  const match = noteText.match(new RegExp(`${escapedStart}\\n([\\s\\S]*?)\\n${escapedEnd}`));
  return {
    start: match?.index ?? -1,
    end: match ? (match.index ?? 0) + match[0].length : -1,
    body: match ? match[1].trim() : null,
  };
}

function replaceSnapshot(noteText, snapshotText) {
  const existing = extractEmbeddedSnapshot(noteText);
  if (existing.start === -1) {
    const tail = noteText.trimEnd();
    return `${tail}\n\n${snapshotText}\n`;
  }
  return `${noteText.slice(0, existing.start)}${snapshotText}${noteText.slice(existing.end)}`;
}

function normalizeSnapshotText(text) {
  return text.replace(/\r\n/g, '\n').trim();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export async function syncObsidianReadiness({
  manifestPath,
  contractManifestPath = null,
  notePath,
  expectedReleaseCandidate = null,
  check = false,
  apply = false,
  pathReportBuilder = buildPathReport,
} = {}) {
  assert.ok(manifestPath, 'manifestPath required');
  assert.ok(notePath, 'notePath required');

  const manifest = await readJSON(manifestPath);
  const contractManifest = contractManifestPath ? await readJSON(contractManifestPath) : null;
  validateManifest(manifest, { strictRelease: false });
  const summary = summarizeGaps(manifest, {
    expectedReleaseCandidate,
    strictPathReport: pathReportBuilder({ strictStaging: true, ci: process.env.CI === 'true' }),
    contractManifest,
  });
  const snapshotBody = normalizeSnapshotText(formatObsidian(summary));
  const newSnapshot = formatSnapshot(summary);
  const noteText = await readFile(notePath, 'utf8');
  const existing = extractEmbeddedSnapshot(noteText);

  if (check) {
    if (existing.body === null) {
      throw new Error(`Obsidian readiness snapshot markers are missing from ${notePath}`);
    }
    if (normalizeSnapshotText(existing.body) !== snapshotBody) {
      throw new Error(`Obsidian readiness snapshot is stale for ${notePath}`);
    }
    return { updated: false, changed: false };
  }

  if (apply) {
    const updated = replaceSnapshot(noteText, newSnapshot);
    if (updated !== noteText) {
      await writeFile(notePath, updated, 'utf8');
    }
    return { updated: true, changed: updated !== noteText };
  }

  return {
    updated: false,
    changed: false,
    snapshot: newSnapshot,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await syncObsidianReadiness({
    manifestPath: args.manifest,
    contractManifestPath: args.contractManifest,
    notePath: args.note,
    expectedReleaseCandidate: args.expectedReleaseCandidate ?? readCurrentGitHead(process.cwd()),
    check: args.check,
    apply: args.apply,
  });

  if (result.snapshot) {
    process.stdout.write(`${result.snapshot}\n`);
  } else if (args.check) {
    console.log(`Obsidian readiness snapshot is in sync: ${args.note}: ${obsidianReadinessProofMarkers.join(', ')}`);
  } else if (result.changed) {
    console.log(`Updated Obsidian readiness snapshot in ${args.note}`);
  }
}

function readCurrentGitHead(cwd) {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('sync-obsidian-readiness.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
