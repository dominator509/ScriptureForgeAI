import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import { parseArgs, parseDivergence, verifyProductionReadiness } from './verify-production-readiness.mjs';
import { requiredIds } from './validate-staging-evidence.mjs';
import { gateDefinitions } from './run-local-gates.mjs';

const sha = '0123456789abcdef0123456789abcdef01234567';

test('parseArgs supports manifest and cwd', () => {
  const args = parseArgs(['--manifest', 'manifest.json', '--local-gate-report', 'local-gates.json', '--cwd', 'repo']);
  assert.equal(args.manifestPath, 'manifest.json');
  assert.equal(args.localGateReportPath, 'local-gates.json');
  assert.equal(args.cwd, 'repo');
});

test('parseDivergence reads ahead and behind counts', () => {
  assert.deepEqual(parseDivergence('## main...origin/main [ahead 2, behind 3]'), { ahead: 2, behind: 3 });
  assert.deepEqual(parseDivergence('## main...origin/main'), { ahead: 0, behind: 0 });
});

test('verifyProductionReadiness accepts strict manifest on clean synced HEAD', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    const localGateReportPath = join(dir, 'local-gates.json');
    await writeFile(manifestPath, JSON.stringify(strictManifest(sha)), 'utf8');
    await writeFile(localGateReportPath, JSON.stringify(localGateReport()), 'utf8');
    const result = await verifyProductionReadiness({
      manifestPath,
      localGateReportPath,
      cwd: dir,
      git: fakeGit({
        status: '## main...origin/main\n',
        head: sha,
      }),
    });

    assert.equal(result.releaseCandidate, sha);
    assert.equal(result.evidenceItems, requiredIds.length);
    assert.equal(result.localGates, gateDefinitions.length);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects dirty worktree', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    const localGateReportPath = join(dir, 'local-gates.json');
    await writeFile(manifestPath, JSON.stringify(strictManifest(sha)), 'utf8');
    await writeFile(localGateReportPath, JSON.stringify(localGateReport()), 'utf8');
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n M README.md\n',
          head: sha,
        }),
      }),
      /worktree must be clean/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects unsynced branch', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    const localGateReportPath = join(dir, 'local-gates.json');
    await writeFile(manifestPath, JSON.stringify(strictManifest(sha)), 'utf8');
    await writeFile(localGateReportPath, JSON.stringify(localGateReport()), 'utf8');
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main [ahead 1]\n',
          head: sha,
        }),
      }),
      /must not be ahead/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects manifest SHA drift', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    const localGateReportPath = join(dir, 'local-gates.json');
    await writeFile(manifestPath, JSON.stringify(strictManifest('fedcba9876543210fedcba9876543210fedcba98')), 'utf8');
    await writeFile(localGateReportPath, JSON.stringify(localGateReport()), 'utf8');
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
      }),
      /release_candidate must equal current git HEAD SHA/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects local gate report SHA drift', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    const localGateReportPath = join(dir, 'local-gates.json');
    await writeFile(manifestPath, JSON.stringify(strictManifest(sha)), 'utf8');
    await writeFile(localGateReportPath, JSON.stringify(localGateReport({
      gitHead: 'fedcba9876543210fedcba9876543210fedcba98',
    })), 'utf8');
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
      }),
      /local gate report git_head must equal current git HEAD SHA/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects missing local gate report', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    await writeFile(manifestPath, JSON.stringify(strictManifest(sha)), 'utf8');
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath: join(dir, 'missing-local-gates.json'),
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
      }),
      /ENOENT/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects dry-run local gate report', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    const localGateReportPath = join(dir, 'local-gates.json');
    await writeFile(manifestPath, JSON.stringify(strictManifest(sha)), 'utf8');
    await writeFile(localGateReportPath, JSON.stringify(localGateReport({ dryRun: true })), 'utf8');
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
      }),
      /dry-run reports cannot satisfy local gate evidence/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function fakeGit({ status, head }) {
  return (args) => {
    if (args.join(' ') === 'status --porcelain=v1 --branch') {
      return status;
    }
    if (args.join(' ') === 'rev-parse HEAD') {
      return `${head}\n`;
    }
    throw new Error(`unexpected git args ${args.join(' ')}`);
  };
}

function localGateReport({ dryRun = false, gitHead = sha } = {}) {
  return {
    schema_version: 1,
    git_head: gitHead,
    observed_at: '2026-06-25T12:00:00Z',
    duration_ms: 100,
    threshold_pass: true,
    dry_run: dryRun,
    gates_total: gateDefinitions.length,
    gates_run: gateDefinitions.length,
    gates_failed: 0,
    results: gateDefinitions.map((gate, index) => ({
      id: gate.id,
      command: gate.command.join(' '),
      cwd: gate.cwd ?? '.',
      skipped: dryRun,
      exit_code: 0,
      duration_ms: index,
      stdout_tail: '',
      stderr_tail: '',
    })),
  };
}

function strictManifest(releaseCandidate) {
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: releaseCandidate,
    generated_at: '2026-06-25T00:00:00Z',
    items: requiredIds.map((id) => ({
      id,
      category: 'test',
      status: id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
      description: `${id} proof`,
      ...(id === 'SEC-SIGNOFF-001'
        ? { decision_ref: 'security/dependency_risk_register.md#DRR-001' }
        : {
            evidence: [
              {
                observed_at: '2026-06-25T12:00:00Z',
                command_or_probe: 'probe',
                artifact: `artifacts/${id}.json`,
                result_summary: 'passed',
              },
            ],
          }),
    })),
  };
}
