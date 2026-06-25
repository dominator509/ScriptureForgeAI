import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { validateLocalGateReport } from './validate-local-gate-report.mjs';
import { validateManifest } from './validate-staging-evidence.mjs';

export function parseArgs(argv) {
  const args = {
    manifestPath: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.staging.json',
    localGateReportPath: process.env.LOCAL_GATE_REPORT_FILE ?? 'artifacts/local-gate-report.json',
    cwd: process.cwd(),
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--manifest') {
      args.manifestPath = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--cwd') {
      args.cwd = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--local-gate-report') {
      args.localGateReportPath = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

export async function verifyProductionReadiness({ manifestPath, localGateReportPath, cwd = process.cwd(), git = realGit } = {}) {
  assert.ok(manifestPath, '--manifest or STAGING_EVIDENCE_FILE is required');
  assert.ok(localGateReportPath, '--local-gate-report or LOCAL_GATE_REPORT_FILE is required');

  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  validateManifest(manifest, { strictRelease: true });
  const localGateReport = JSON.parse(await readFile(localGateReportPath, 'utf8'));
  const localGateResult = validateLocalGateReport(localGateReport);

  const gitState = readGitState(cwd, git);
  assert.equal(gitState.clean, true, `git worktree must be clean before production readiness claim: ${gitState.dirtySummary}`);
  assert.equal(gitState.ahead, 0, `git branch must not be ahead of upstream before production readiness claim: ahead ${gitState.ahead}`);
  assert.equal(gitState.behind, 0, `git branch must not be behind upstream before production readiness claim: behind ${gitState.behind}`);
  assert.equal(manifest.release_candidate, gitState.headSHA, 'manifest release_candidate must equal current git HEAD SHA');

  return {
    releaseCandidate: manifest.release_candidate,
    branchLine: gitState.branchLine,
    evidenceItems: manifest.items.length,
    localGates: localGateResult.gateCount,
  };
}

export function readGitState(cwd, git = realGit) {
  const status = git(['status', '--porcelain=v1', '--branch'], cwd);
  const lines = status.split(/\r?\n/).filter(Boolean);
  const branchLine = lines[0] ?? '';
  const dirtyLines = lines.slice(1);
  const divergence = parseDivergence(branchLine);
  return {
    branchLine,
    clean: dirtyLines.length === 0,
    dirtySummary: dirtyLines.slice(0, 8).join('; '),
    ahead: divergence.ahead,
    behind: divergence.behind,
    headSHA: git(['rev-parse', 'HEAD'], cwd).trim(),
  };
}

export function parseDivergence(branchLine) {
  const aheadMatch = branchLine.match(/ahead (\d+)/);
  const behindMatch = branchLine.match(/behind (\d+)/);
  return {
    ahead: aheadMatch ? Number(aheadMatch[1]) : 0,
    behind: behindMatch ? Number(behindMatch[1]) : 0,
  };
}

function realGit(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await verifyProductionReadiness(args);
  console.log(`production readiness claim verified for ${result.releaseCandidate} (${result.evidenceItems} evidence items, ${result.localGates} local gates)`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('verify-production-readiness.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
