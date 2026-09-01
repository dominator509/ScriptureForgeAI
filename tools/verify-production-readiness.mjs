import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { validateLocalGateReport } from './validate-local-gate-report.mjs';
import { validateManifest } from './validate-staging-evidence.mjs';
import { buildPathReport } from './verify-project-path.mjs';
import { syncObsidianReadiness } from './sync-obsidian-readiness.mjs';
import { summarizeGaps } from './report-staging-evidence-gaps.mjs';

export const productionReadinessProofMarkers = [
  'strict_release_manifest_validated=true',
  'local_gate_report_validated=true',
  'strict_staging_path_validated=true',
  'clean_synced_git_required=true',
  'git_remote_tracking_refreshed=true',
  'release_candidate_matches_git_head=true',
  'local_gate_head_matches_git_head=true',
  'local_gate_branch_matches_current=true',
  'local_gate_upstream_matches_current=true',
  'local_gate_newer_than_manifest=true',
  'local_gate_freshness_checked=true',
  'obsidian_snapshot_current=true',
  'staging_gap_report_clear=true',
  'accepted_risk_zero_required=true',
  'staging_gap_report_footer_contract_validated=true',
];

export const maxLocalGateReportAgeMs = 24 * 60 * 60 * 1000;

export function parseArgs(argv) {
  const args = {
    manifestPath: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.staging.json',
    localGateReportPath: process.env.LOCAL_GATE_REPORT_FILE ?? 'artifacts/local-gate-report.json',
    contractManifestPath: process.env.STAGING_EVIDENCE_CONTRACT_FILE ?? 'production-readiness/staging-evidence.example.json',
    obsidianNotePath: process.env.OBSIDIAN_READINESS_NOTE ?? 'production-readiness/obsidian-production-readiness.md',
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
    } else if (argv[i] === '--contract-manifest') {
      args.contractManifestPath = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--obsidian-note') {
      args.obsidianNotePath = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

export async function verifyProductionReadiness({ manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath, cwd = process.cwd(), git = realGit, pathReportBuilder = buildPathReport, now = process.env.PRODUCTION_READINESS_VALIDATION_NOW ?? new Date() } = {}) {
  assert.ok(manifestPath, '--manifest or STAGING_EVIDENCE_FILE is required');
  assert.ok(localGateReportPath, '--local-gate-report or LOCAL_GATE_REPORT_FILE is required');
  assert.ok(contractManifestPath, '--contract-manifest or STAGING_EVIDENCE_CONTRACT_FILE is required');
  assert.ok(obsidianNotePath, '--obsidian-note or OBSIDIAN_READINESS_NOTE is required');

  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  const contractManifest = JSON.parse(await readFile(contractManifestPath, 'utf8'));
  const localGateReport = JSON.parse(await readFile(localGateReportPath, 'utf8'));
  const localGateResult = validateLocalGateReport(localGateReport);
  const pathReport = pathReportBuilder({ strictStaging: true });
  assert.equal(
    pathReport.threshold_pass,
    true,
    `strict staging PATH readiness must pass before production readiness claim: ${missingStrictPathCommands(pathReport).join('; ')}`,
  );
  const gapSummary = summarizeGaps(manifest, {
    expectedReleaseCandidate: manifest.release_candidate,
    strictPathReport: pathReport,
    contractManifest,
  });
  assert.equal(
    gapSummary.strict_release_ready,
    true,
    `staging evidence gap report must be clear before production readiness claim: ${formatGapBlockers(gapSummary.blocking_items)}`,
  );
  assert.equal(
    gapSummary.accepted_risk,
    0,
    `production readiness claim requires zero accepted-risk items; found ${gapSummary.accepted_risk}`,
  );
  validateManifest(manifest, { strictRelease: true });
  const gitState = readGitState(cwd, git);
  assert.equal(gitState.clean, true, `git worktree must be clean before production readiness claim: ${gitState.dirtySummary}`);
  assert.equal(gitState.ahead, 0, `git branch must not be ahead of upstream before production readiness claim: ahead ${gitState.ahead}`);
  assert.equal(gitState.behind, 0, `git branch must not be behind upstream before production readiness claim: behind ${gitState.behind}`);
  assert.equal(manifest.release_candidate, gitState.headSHA, 'manifest release_candidate must equal current git HEAD SHA');
  assert.equal(localGateResult.gitHead, gitState.headSHA, 'local gate report git_head must equal current git HEAD SHA');
  assert.equal(localGateReport.git_branch, gitState.branch, 'local gate report git_branch must equal current git branch');
  assert.equal(localGateReport.git_upstream, gitState.upstream, 'local gate report git_upstream must equal current git upstream');
  assert.ok(
    localGateReport.observed_at >= manifest.generated_at,
    `local gate report observed_at ${localGateReport.observed_at} must be at or after staging manifest generated_at ${manifest.generated_at}`,
  );
  assertLocalGateReportFresh(localGateReport.observed_at, now);
  await syncObsidianReadiness({
    manifestPath,
    contractManifestPath,
    notePath: obsidianNotePath,
    expectedReleaseCandidate: gitState.headSHA,
    check: true,
    pathReportBuilder: () => pathReport,
  });

  return {
    releaseCandidate: manifest.release_candidate,
    branchLine: gitState.branchLine,
    evidenceItems: manifest.items.length,
    localGates: localGateResult.gateCount,
    obsidianNote: obsidianNotePath,
    stagingPathCommands: pathReport.required.length + pathReport.optional.filter((command) => command.required).length,
    proofMarkers: productionReadinessProofMarkers,
  };
}

function formatGapBlockers(blockingItems) {
  return blockingItems.map((item) => {
    const evidence = Array.isArray(item.required_evidence) && item.required_evidence.length > 0
      ? ` (${item.required_evidence.join('; ')})`
      : '';
    return `${item.id}${evidence}`;
  }).join(', ');
}

function assertLocalGateReportFresh(observedAt, now) {
  const observedAtMs = parseTimeMs(observedAt, 'local gate report observed_at');
  const nowMs = parseTimeMs(now, 'production readiness verification time');
  assert.ok(
    observedAtMs <= nowMs,
    `local gate report observed_at ${observedAt} must not be after production readiness verification time ${new Date(nowMs).toISOString()}`,
  );
  assert.ok(
    nowMs - observedAtMs <= maxLocalGateReportAgeMs,
    `local gate report observed_at ${observedAt} must be within 24 hours of production readiness verification time ${new Date(nowMs).toISOString()}`,
  );
}

function parseTimeMs(value, label) {
  const ms = value instanceof Date ? value.getTime() : Date.parse(value);
  assert.ok(Number.isFinite(ms), `${label} must be a valid timestamp`);
  return ms;
}

export function readGitState(cwd, git = realGit) {
  refreshGitRemoteState(cwd, git);
  const status = git(['status', '--porcelain=v1', '--branch'], cwd);
  const lines = status.split(/\r?\n/).filter(Boolean);
  const branchLine = lines[0] ?? '';
  const dirtyLines = lines.slice(1);
  const divergence = parseDivergence(branchLine);
  return {
    branchLine,
    branch: parseBranchLine(branchLine).branch,
    upstream: parseBranchLine(branchLine).upstream,
    clean: dirtyLines.length === 0,
    dirtySummary: dirtyLines.slice(0, 8).join('; '),
    ahead: divergence.ahead,
    behind: divergence.behind,
    headSHA: git(['rev-parse', 'HEAD'], cwd).trim(),
  };
}

function refreshGitRemoteState(cwd, git) {
  try {
    git(['fetch', '--dry-run'], cwd);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`git fetch --dry-run must succeed before production readiness claim: ${message}`);
  }
}

export function parseBranchLine(branchLine) {
  const withoutPrefix = branchLine.replace(/^##\s*/, '');
  const branchAndUpstream = withoutPrefix.split(/\s+\[/, 1)[0] ?? '';
  const [branch = '', upstream = ''] = branchAndUpstream.split('...');
  return { branch, upstream };
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

function missingStrictPathCommands(report) {
  return [
    ...report.required,
    ...report.optional.filter((command) => command.required),
  ]
    .filter((command) => !command.ok)
    .map((command) => {
      if (command.remediation) {
        return `${command.name} (${command.remediation})`;
      }
      return command.name;
    });
}

export function buildGapReportHint({ argv = [], env = process.env } = {}) {
  let manifestPath = env.STAGING_EVIDENCE_FILE;
  let contractManifestPath = env.STAGING_EVIDENCE_CONTRACT_FILE;
  if (!manifestPath) {
    try {
      const args = parseArgs(argv);
      manifestPath = args.manifestPath;
      contractManifestPath ||= args.contractManifestPath;
    } catch {
      manifestPath = 'production-readiness/staging-evidence.staging.json';
      contractManifestPath ||= 'production-readiness/staging-evidence.example.json';
    }
  }
  if (!contractManifestPath) {
    try {
      contractManifestPath = parseArgs(argv).contractManifestPath;
    } catch {
      contractManifestPath = 'production-readiness/staging-evidence.example.json';
    }
  }
  const manifestArg = env.STAGING_EVIDENCE_FILE ? '' : ` --manifest ${manifestPath}`;
  const contractManifestArg = env.STAGING_EVIDENCE_CONTRACT_FILE ? '' : ` --contract-manifest ${contractManifestPath}`;
  return `Run node tools/report-staging-evidence-gaps.mjs${manifestArg}${contractManifestArg} --expected-release-candidate <current git SHA> for the full blocker list.`;
}

export async function buildFailureDiagnostics({ argv = [], env = process.env, pathReportBuilder = buildPathReport } = {}) {
  try {
    const args = parseArgs(argv);
    const manifestPath = env.STAGING_EVIDENCE_FILE ?? args.manifestPath;
    const contractManifestPath = env.STAGING_EVIDENCE_CONTRACT_FILE ?? args.contractManifestPath;
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    const contractManifest = JSON.parse(await readFile(contractManifestPath, 'utf8'));
    const pathReport = pathReportBuilder({ strictStaging: true });
    const gapSummary = summarizeGaps(manifest, {
      expectedReleaseCandidate: manifest.release_candidate,
      strictPathReport: pathReport,
      contractManifest,
    });
    if (gapSummary.strict_release_ready && gapSummary.blocking_items.length === 0) {
      return '';
    }
    const blockerIDs = gapSummary.blocking_items.map((item) => item.id).join(', ');
    return [
      `staging evidence blockers still present: ${blockerIDs || 'none'}`,
      `staging evidence status counts: passed=${gapSummary.passed}, pending_external=${gapSummary.pending_external}, blocked=${gapSummary.blocked}, failed=${gapSummary.failed}, accepted_risk=${gapSummary.accepted_risk}, non_manifest=${gapSummary.non_manifest_blockers}`,
      `strict_staging_path_ready=${gapSummary.strict_staging_path_ready ? 'yes' : 'no'}, strict_release_ready=${gapSummary.strict_release_ready ? 'yes' : 'no'}`,
    ].join('\n');
  } catch (error) {
    return `staging evidence blocker diagnostics unavailable: ${error instanceof Error ? error.message : String(error)}`;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = await verifyProductionReadiness(args);
  console.log(`production readiness claim verified for ${result.releaseCandidate} (${result.evidenceItems} evidence items, ${result.localGates} local gates, ${result.stagingPathCommands} staging PATH tools, Obsidian note ${result.obsidianNote})`);
  console.log(`proof markers: ${result.proofMarkers.join(', ')}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('verify-production-readiness.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    buildFailureDiagnostics({ argv: process.argv.slice(2) })
      .then((diagnostics) => {
        if (diagnostics) {
          console.error(diagnostics);
        }
        console.error(buildGapReportHint({ argv: process.argv.slice(2) }));
        process.exit(1);
      })
      .catch((diagnosticError) => {
        console.error(`staging evidence blocker diagnostics unavailable: ${diagnosticError.message}`);
        console.error(buildGapReportHint({ argv: process.argv.slice(2) }));
        process.exit(1);
      });
  });
}
