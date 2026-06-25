import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export const requiredIds = [
  'SRC-CI-001',
  'DEPLOY-TF-001',
  'DEPLOY-TLS-001',
  'DEPLOY-K8S-001',
  'SEC-SECRETS-001',
  'SEC-DBUSER-001',
  'ABUSE-LIMIT-001',
  'DATA-RLS-001',
  'DATA-REDIS-001',
  'RUST-GRPC-001',
  'OBS-OTEL-001',
  'OBS-ALERT-001',
  'CLIENT-WEB-001',
  'CLIENT-MOBILE-001',
  'EXT-ZOOM-001',
  'EXT-AI-001',
  'PERF-HTTP-001',
  'PERF-WS-001',
  'DR-ROLLBACK-001',
  'DR-BACKUP-001',
  'SEC-SIGNOFF-001',
];

const allowedStatuses = new Set([
  'pending_external',
  'passed',
  'failed',
  'blocked',
  'accepted_risk',
]);

export function parseArgs(argv) {
  const args = {
    evidenceFile: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.example.json',
    strictRelease: process.env.STAGING_EVIDENCE_STRICT_RELEASE === 'true',
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--manifest') {
      args.evidenceFile = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--strict-release') {
      args.strictRelease = true;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

export function validateManifest(manifest, { strictRelease = false } = {}) {
  assert.equal(manifest.schema_version, 1, 'staging evidence schema_version must be 1');
  assert.equal(typeof manifest.environment, 'string', 'environment is required');
  assert.ok(manifest.environment.length > 0, 'environment must not be empty');
  assert.equal(typeof manifest.release_candidate, 'string', 'release_candidate is required');
  assert.ok(manifest.release_candidate.length > 0, 'release_candidate must not be empty');
  assert.match(manifest.generated_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'generated_at must be an ISO UTC timestamp without milliseconds');
  assert.ok(Array.isArray(manifest.items), 'items must be an array');

  const itemsById = new Map();
  for (const item of manifest.items) {
    assert.equal(typeof item.id, 'string', 'item id is required');
    assert.ok(!itemsById.has(item.id), `duplicate evidence item ${item.id}`);
    itemsById.set(item.id, item);
  }

  for (const id of requiredIds) {
    assert.ok(itemsById.has(id), `staging evidence manifest missing ${id}`);
  }

  for (const item of manifest.items) {
    validateItem(item);
  }

  if (strictRelease) {
    validateStrictRelease(manifest);
  }

  return {
    items: manifest.items.length,
    strictRelease,
  };
}

function validateItem(item) {
  assert.equal(typeof item.category, 'string', `${item.id} category is required`);
  assert.ok(item.category.length > 0, `${item.id} category must not be empty`);
  assert.ok(allowedStatuses.has(item.status), `${item.id} has invalid status ${item.status}`);
  assert.equal(typeof item.description, 'string', `${item.id} description is required`);
  assert.ok(item.description.length > 0, `${item.id} description must not be empty`);

  if (item.status === 'pending_external') {
    assert.ok(Array.isArray(item.required_evidence), `${item.id} pending item must list required_evidence`);
    assert.ok(item.required_evidence.length > 0, `${item.id} pending item must have at least one required evidence entry`);
  }

  if (item.status === 'passed') {
    assert.ok(Array.isArray(item.evidence), `${item.id} passed item must include evidence artifacts`);
    assert.ok(item.evidence.length > 0, `${item.id} passed item must have at least one evidence artifact`);
    for (const artifact of item.evidence) {
      assert.equal(typeof artifact.observed_at, 'string', `${item.id} evidence observed_at is required`);
      assert.match(artifact.observed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, `${item.id} evidence observed_at must be ISO UTC without milliseconds`);
      assert.equal(typeof artifact.command_or_probe, 'string', `${item.id} evidence command_or_probe is required`);
      assert.equal(typeof artifact.artifact, 'string', `${item.id} evidence artifact path or URL is required`);
      assert.equal(typeof artifact.result_summary, 'string', `${item.id} evidence result_summary is required`);
    }
  }

  if (item.status === 'failed' || item.status === 'blocked') {
    assert.equal(typeof item.blocker, 'string', `${item.id} ${item.status} item must explain blocker`);
    assert.ok(item.blocker.length > 0, `${item.id} blocker must not be empty`);
    assert.equal(typeof item.owner, 'string', `${item.id} ${item.status} item must name an owner`);
    assert.ok(item.owner.length > 0, `${item.id} owner must not be empty`);
  }

  if (item.status === 'accepted_risk') {
    assert.equal(typeof item.decision_ref, 'string', `${item.id} accepted risk must reference a decision record`);
    assert.ok(item.decision_ref.length > 0, `${item.id} decision_ref must not be empty`);
  }
}

function validateStrictRelease(manifest) {
  assert.ok(!manifest.release_candidate.toLowerCase().includes('replace-with'), 'strict release manifest must use a real release_candidate');
  for (const item of manifest.items) {
    if (item.id === 'SEC-SIGNOFF-001' && item.status === 'accepted_risk') {
      continue;
    }
    assert.equal(item.status, 'passed', `${item.id} must be passed for strict release validation`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = JSON.parse(await readFile(args.evidenceFile, 'utf8'));
  validateManifest(manifest, { strictRelease: args.strictRelease });
  const strictSuffix = args.strictRelease ? ' in strict release mode' : '';
  console.log(`staging evidence manifest validated${strictSuffix}: ${args.evidenceFile}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-staging-evidence.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
