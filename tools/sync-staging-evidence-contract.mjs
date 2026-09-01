import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { validateManifest } from './validate-staging-evidence.mjs';

export const stagingEvidenceContractProofMarkers = [
  'staging_manifest_validated=true',
  'contract_manifest_validated=true',
  'pending_external_required_evidence_checked=true',
  'non_pending_evidence_preserved=true',
  'contract_drift_zero=true',
];

function usage() {
  return [
    'Usage:',
    '  node tools/sync-staging-evidence-contract.mjs [--manifest <path>] [--contract-manifest <path>] [--check|--apply]',
    '',
    'Refreshes pending_external required_evidence arrays in an environment-specific staging manifest from the checked-in evidence contract.',
  ].join('\n');
}

export function parseArgs(argv) {
  const args = {
    manifest: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.staging.json',
    contractManifest: process.env.STAGING_EVIDENCE_CONTRACT_FILE ?? 'production-readiness/staging-evidence.example.json',
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
    } else if (argv[i] === '--check') {
      args.check = true;
    } else if (argv[i] === '--apply') {
      args.apply = true;
    } else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log(usage());
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${argv[i]}\n${usage()}`);
    }
  }
  assert.ok(args.manifest, '--manifest must not be empty');
  assert.ok(args.contractManifest, '--contract-manifest must not be empty');
  assert.ok(!(args.check && args.apply), '--check and --apply cannot be combined');
  return args;
}

export function syncPendingRequiredEvidence(manifest, contractManifest) {
  validateManifest(manifest, { strictRelease: false });
  validateManifest(contractManifest, { strictRelease: false });

  const contractItems = new Map(contractManifest.items.map((item) => [item.id, item]));
  const nextManifest = structuredClone(manifest);
  const changed = [];

  for (const item of nextManifest.items) {
    if (item.status !== 'pending_external') {
      continue;
    }
    const contractItem = contractItems.get(item.id);
    if (!contractItem || contractItem.status !== 'pending_external') {
      continue;
    }
    const expected = contractItem.required_evidence ?? [];
    const actual = item.required_evidence ?? [];
    if (!sameStringArray(actual, expected)) {
      item.required_evidence = [...expected];
      changed.push({
        id: item.id,
        previous_count: actual.length,
        next_count: expected.length,
      });
    }
  }

  return {
    manifest: nextManifest,
    changed,
    changed_count: changed.length,
  };
}

function sameStringArray(left, right) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length === right.length
    && left.every((value, index) => value === right[index]);
}

async function readJSON(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = await readJSON(args.manifest);
  const contractManifest = await readJSON(args.contractManifest);
  const result = syncPendingRequiredEvidence(manifest, contractManifest);

  if (result.changed_count === 0) {
    console.log(`Staging evidence contract is in sync: ${args.manifest}: ${stagingEvidenceContractProofMarkers.join(', ')}`);
    return;
  }

  const changedIds = result.changed.map((item) => item.id).join(', ');
  if (args.apply) {
    await writeFile(args.manifest, `${JSON.stringify(result.manifest, null, 2)}\n`);
    console.log(`Updated ${args.manifest} pending evidence contract fields: ${changedIds}`);
    return;
  }

  console.error(`Staging evidence contract drift detected in ${args.manifest}: ${changedIds}`);
  console.error('Run with --apply to refresh pending required_evidence fields from the checked-in contract.');
  process.exit(1);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('sync-staging-evidence-contract.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
