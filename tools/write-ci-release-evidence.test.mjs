import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import {
  buildReleaseEvidence,
  ciReleaseEvidenceProofMarkers,
  requiredGates,
  writeReleaseEvidence,
} from './write-ci-release-evidence.mjs';

const env = {
  GITHUB_WORKFLOW: 'Security Pipeline Verification',
  GITHUB_JOB: 'security-audit',
  GITHUB_SHA: '0123456789abcdef0123456789abcdef01234567',
  GITHUB_RUN_ID: '1234567890',
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_RUN_NUMBER: '42',
  GITHUB_REPOSITORY: 'example/scriptureforgeai',
  GITHUB_REF: 'refs/heads/main',
  GITHUB_REF_NAME: 'main',
  GITHUB_REF_TYPE: 'branch',
  GITHUB_EVENT_NAME: 'push',
  GITHUB_ACTOR: 'codex',
  GITHUB_SERVER_URL: 'https://github.com',
};

test('buildReleaseEvidence emits ciprobe-compatible successful run markers', () => {
  const body = buildReleaseEvidence(env);

  assert.match(body, /GitHub Actions release evidence/);
  assert.match(body, /workflow: Security Pipeline Verification/);
  assert.match(body, /job: security-audit/);
  assert.match(body, /ref: refs\/heads\/main/);
  assert.match(body, /ref_name: main/);
  assert.match(body, /event_name: push/);
  assert.match(body, /commit: 0123456789abcdef0123456789abcdef01234567/);
  assert.match(body, /run_attempt: 1/);
  assert.match(body, /run_number: 42/);
  assert.match(body, /source_control_status: clean/);
  assert.match(body, /source_control_clean: verified-before-evidence-write/);
  assert.match(body, /source_control_untracked_status: clean/);
  assert.match(body, /source_control_clean_command: git diff --quiet/);
  assert.match(body, /source_control_cached_clean_command: git diff --cached --quiet/);
  assert.match(body, /source_control_untracked_clean_command: git status --short/);
  assert.match(body, /release_evidence_scope: exact-github-sha-required-gates/);
  assert.match(body, /proof markers:/);
  for (const marker of ciReleaseEvidenceProofMarkers) {
    assert.match(body, new RegExp(escapeRegExp(marker)));
  }
  assert.match(body, /status: completed/);
  assert.match(body, /conclusion: success/);
  for (const gate of requiredGates) {
    assert.match(body, new RegExp(escapeRegExp(gate)));
  }
});

test('buildReleaseEvidence rejects short commit SHAs', () => {
  assert.throws(() => buildReleaseEvidence({ ...env, GITHUB_SHA: '0123456' }), /40-character/);
});

test('buildReleaseEvidence requires source ref and event provenance', () => {
  assert.throws(() => buildReleaseEvidence({ ...env, GITHUB_REF: '' }), /GITHUB_REF is required/);
  assert.throws(() => buildReleaseEvidence({ ...env, GITHUB_REF_NAME: '' }), /GITHUB_REF_NAME is required/);
  assert.throws(() => buildReleaseEvidence({ ...env, GITHUB_EVENT_NAME: '' }), /GITHUB_EVENT_NAME is required/);
});

test('buildReleaseEvidence requires run attempt provenance', () => {
  assert.throws(() => buildReleaseEvidence({ ...env, GITHUB_RUN_ATTEMPT: '' }), /GITHUB_RUN_ATTEMPT is required/);
  assert.throws(() => buildReleaseEvidence({ ...env, GITHUB_RUN_NUMBER: '' }), /GITHUB_RUN_NUMBER is required/);
});

test('writeReleaseEvidence creates parent directory and artifact file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-ci-evidence-'));
  try {
    const outputPath = join(dir, 'nested', 'ci-release-evidence.txt');
    await writeReleaseEvidence({ outputPath, env });
    const body = await readFile(outputPath, 'utf8');
    assert.match(body, /run_url: https:\/\/github\.com\/example\/scriptureforgeai\/actions\/runs\/1234567890/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
