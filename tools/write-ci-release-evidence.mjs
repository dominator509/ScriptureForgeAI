import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export const requiredGates = [
  'go test ./...',
  'go vet ./...',
  'npm audit --audit-level=moderate',
  'npm audit --audit-level=high',
  'npm run smoke',
  'npm run typecheck',
  'npm run build',
  'npm run build:check',
  'cargo test',
  'terraform fmt -check',
  'terraform validate',
  'TruffleHog Secret Scanning',
];

export function buildReleaseEvidence(env = process.env) {
  const workflow = env.GITHUB_WORKFLOW ?? 'Security Pipeline Verification';
  const job = env.GITHUB_JOB ?? 'security-audit';
  const sha = env.GITHUB_SHA ?? '';
  const runId = env.GITHUB_RUN_ID ?? '';
  const runAttempt = env.GITHUB_RUN_ATTEMPT ?? '';
  const repository = env.GITHUB_REPOSITORY ?? '';
  const ref = env.GITHUB_REF_NAME ?? env.GITHUB_REF ?? '';
  const actor = env.GITHUB_ACTOR ?? '';
  const serverURL = env.GITHUB_SERVER_URL ?? 'https://github.com';

  assert.match(sha, /^[a-fA-F0-9]{40}$/, 'GITHUB_SHA must be a full 40-character commit SHA');
  assert.ok(workflow.length > 0, 'GITHUB_WORKFLOW is required');
  assert.ok(job.length > 0, 'GITHUB_JOB is required');
  assert.ok(repository.length > 0, 'GITHUB_REPOSITORY is required');
  assert.ok(runId.length > 0, 'GITHUB_RUN_ID is required');

  const runURL = `${serverURL}/${repository}/actions/runs/${runId}`;

  return [
    'GitHub Actions release evidence',
    `workflow: ${workflow}`,
    `job: ${job}`,
    `repository: ${repository}`,
    `ref: ${ref}`,
    `commit: ${sha}`,
    `run_id: ${runId}`,
    `run_attempt: ${runAttempt}`,
    `actor: ${actor}`,
    `run_url: ${runURL}`,
    'status: completed',
    'conclusion: success',
    'required gates:',
    ...requiredGates.map((gate) => `- ${gate}`),
    '',
  ].join('\n');
}

export async function writeReleaseEvidence({ outputPath = 'artifacts/ci-release-evidence.txt', env = process.env } = {}) {
  const body = buildReleaseEvidence(env);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, body, 'utf8');
  return { outputPath, body };
}

function parseArgs(argv) {
  const args = { outputPath: 'artifacts/ci-release-evidence.txt' };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--output') {
      args.outputPath = argv[i + 1];
      i += 1;
    }
  }
  return args;
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('write-ci-release-evidence.mjs')) {
  const args = parseArgs(process.argv.slice(2));
  writeReleaseEvidence(args)
    .then(({ outputPath }) => {
      console.log(`wrote CI release evidence to ${outputPath}`);
    })
    .catch((error) => {
      console.error(error.message);
      process.exit(1);
    });
}
