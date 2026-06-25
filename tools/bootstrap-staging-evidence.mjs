import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { validateManifest } from './validate-staging-evidence.mjs';

function usage() {
  return [
    'Usage:',
    '  node tools/bootstrap-staging-evidence.mjs [--template <path>] [--out <path>] [--environment <name>] [--release-candidate <sha-or-tag>] [--force]',
    '',
    'Creates an environment-specific staging evidence manifest from the checked-in contract.',
    'The generated manifest is non-strict by design: evidence items remain pending_external until real artifacts are recorded.',
  ].join('\n');
}

export function parseArgs(argv) {
  const args = {
    template: 'production-readiness/staging-evidence.example.json',
    out: 'production-readiness/staging-evidence.staging.json',
    environment: 'staging',
    releaseCandidate: undefined,
    force: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--template') {
      args.template = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--out') {
      args.out = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--environment') {
      args.environment = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--release-candidate') {
      args.releaseCandidate = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--force') {
      args.force = true;
    } else {
      throw new Error(`unknown argument ${argv[i]}\n${usage()}`);
    }
  }

  assert.ok(args.template, '--template must not be empty');
  assert.ok(args.out, '--out must not be empty');
  assert.ok(args.environment, '--environment must not be empty');
  return args;
}

export function bootstrapManifest(template, { environment, releaseCandidate, generatedAt }) {
  assert.ok(environment?.trim(), 'environment is required');
  assert.ok(releaseCandidate?.trim(), 'releaseCandidate is required');
  assert.match(generatedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'generatedAt must be ISO UTC without milliseconds');

  const manifest = structuredClone(template);
  manifest.environment = environment;
  manifest.release_candidate = releaseCandidate;
  manifest.generated_at = generatedAt;
  manifest.items = manifest.items.map((item) => {
    assert.ok(Array.isArray(item.required_evidence), `${item.id} template item must include required_evidence`);
    return {
      id: item.id,
      category: item.category,
      status: 'pending_external',
      description: item.description,
      required_evidence: item.required_evidence,
    };
  });
  validateManifest(manifest);
  return manifest;
}

async function readJSON(path) {
  const content = await readFile(path, 'utf8');
  return JSON.parse(content.replace(/^\uFEFF/, ''));
}

function currentGitSHA(cwd = process.cwd()) {
  return execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim();
}

async function writeManifest(path, manifest, { force }) {
  if (!force) {
    try {
      await readFile(path, 'utf8');
      throw new Error(`${path} already exists; pass --force to overwrite`);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const template = await readJSON(args.template);
  const releaseCandidate = args.releaseCandidate ?? currentGitSHA();
  const generatedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const manifest = bootstrapManifest(template, {
    environment: args.environment,
    releaseCandidate,
    generatedAt,
  });
  await writeManifest(args.out, manifest, { force: args.force });
  console.log(`staging evidence manifest bootstrapped: ${args.out} (${args.environment}, ${releaseCandidate})`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('bootstrap-staging-evidence.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
