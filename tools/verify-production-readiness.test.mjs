import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
import {
  buildFailureDiagnostics,
  buildGapReportHint,
  maxLocalGateReportAgeMs,
  parseArgs,
  parseBranchLine,
  parseDivergence,
  productionReadinessProofMarkers,
  verifyProductionReadiness,
} from './verify-production-readiness.mjs';
import { ciEvidenceGateProofMarkers } from './validate-ci-evidence-gates.mjs';
import { ciWorkflowProofMarkers, requiredMarkers as ciWorkflowRequiredMarkers } from './validate-ci-workflow.mjs';
import { dependencyRiskProofMarkers } from './validate-dependency-risk.mjs';
import { deploymentSkeletonProofMarkers } from './validate-deployment-skeleton.mjs';
import { requiredIds } from './validate-staging-evidence.mjs';
import { gateDefinitions } from './run-local-gates.mjs';
import { journalCryptoProofMarkers } from './verify-journal-crypto.mjs';
import { observabilityProofMarkers } from './validate-observability.mjs';
import { obsidianReadinessProofMarkers, syncObsidianReadiness } from './sync-obsidian-readiness.mjs';
import { rlsDBProofMarkers } from './run-rls-db-integration.mjs';
import { rustProtobufProofMarkers } from './verify-rust-protobuf.mjs';
import { securityArtifactsProofMarkers } from './validate-security-artifacts.mjs';
import { secretHygieneProofMarkers } from './validate-secret-hygiene.mjs';
import { stagingEvidenceContractProofMarkers } from './sync-staging-evidence-contract.mjs';
import { stagingEvidenceProofMarkers } from './validate-staging-evidence.mjs';
import { ciReleaseEvidenceProofMarkers } from './write-ci-release-evidence.mjs';
import { stagingEvidenceGapReportProofMarkers } from './report-staging-evidence-gaps.mjs';
import { projectPathProofMarkers, strictStagingPathProofMarkers } from './verify-project-path.mjs';
import { goTestProofMarkers, goVetProofMarkers } from './run-go-core-gate.mjs';
import { goProbeProofMarkers } from './run-go-probe-tests.mjs';
import { npmAuditCompletedMarkers } from './run-npm-audit.mjs';
import { terraformFmtProofMarkers, terraformValidateProofMarkers } from './run-terraform-command.mjs';
import { terraformInitProofMarkers } from './run-terraform-init.mjs';
import {
  mobileBuildCheckProofMarkers,
  mobileSmokeProofMarkers,
  rustCargoProofMarkers,
  webBuildProofMarkers,
  webSmokeProofMarkers,
  webTypecheckProofMarkers,
} from './validate-local-gate-report.mjs';

const sha = '0123456789abcdef0123456789abcdef01234567';
process.env.PRODUCTION_READINESS_VALIDATION_NOW = '2026-06-26T01:00:00Z';

test('parseArgs supports manifest, contract, and cwd', () => {
  const args = parseArgs(['--manifest', 'manifest.json', '--contract-manifest', 'contract.json', '--local-gate-report', 'local-gates.json', '--obsidian-note', 'obsidian.md', '--cwd', 'repo']);
  assert.equal(args.manifestPath, 'manifest.json');
  assert.equal(args.contractManifestPath, 'contract.json');
  assert.equal(args.localGateReportPath, 'local-gates.json');
  assert.equal(args.obsidianNotePath, 'obsidian.md');
  assert.equal(args.cwd, 'repo');
});

test('parseDivergence reads ahead and behind counts', () => {
  assert.deepEqual(parseDivergence('## main...origin/main [ahead 2, behind 3]'), { ahead: 2, behind: 3 });
  assert.deepEqual(parseDivergence('## main...origin/main'), { ahead: 0, behind: 0 });
});

test('parseBranchLine reads current branch and upstream', () => {
  assert.deepEqual(parseBranchLine('## main...origin/main [ahead 2, behind 3]'), { branch: 'main', upstream: 'origin/main' });
  assert.deepEqual(parseBranchLine('## codex/production-readiness-remediation...origin/codex/production-readiness-remediation'), {
    branch: 'codex/production-readiness-remediation',
    upstream: 'origin/codex/production-readiness-remediation',
  });
  assert.deepEqual(parseBranchLine('## HEAD (no branch)'), { branch: 'HEAD (no branch)', upstream: '' });
});

test('buildGapReportHint points failed final claims to the full blocker report', () => {
  assert.equal(
    buildGapReportHint({
      argv: ['--manifest', 'production-readiness/example.json', '--contract-manifest', 'production-readiness/contract.json'],
      env: {},
    }),
    'Run node tools/report-staging-evidence-gaps.mjs --manifest production-readiness/example.json --contract-manifest production-readiness/contract.json --expected-release-candidate <current git SHA> for the full blocker list.',
  );
  assert.equal(
    buildGapReportHint({
      argv: ['--unknown'],
      env: {},
    }),
    'Run node tools/report-staging-evidence-gaps.mjs --manifest production-readiness/staging-evidence.staging.json --contract-manifest production-readiness/staging-evidence.example.json --expected-release-candidate <current git SHA> for the full blocker list.',
  );
  assert.equal(
    buildGapReportHint({
      argv: ['--manifest', 'ignored.json', '--contract-manifest', 'contract-from-argv.json'],
      env: { STAGING_EVIDENCE_FILE: 'from-env.json' },
    }),
    'Run node tools/report-staging-evidence-gaps.mjs --contract-manifest contract-from-argv.json --expected-release-candidate <current git SHA> for the full blocker list.',
  );
  assert.equal(
    buildGapReportHint({
      argv: ['--manifest', 'manifest-from-argv.json', '--contract-manifest', 'ignored-contract.json'],
      env: { STAGING_EVIDENCE_CONTRACT_FILE: 'contract-from-env.json' },
    }),
    'Run node tools/report-staging-evidence-gaps.mjs --manifest manifest-from-argv.json --expected-release-candidate <current git SHA> for the full blocker list.',
  );
});

test('buildFailureDiagnostics reports staging blocker IDs and counts', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifest = strictManifest(sha);
    const blocked = manifest.items.find((item) => item.id === 'SRC-CI-001');
    const contract = contractManifest();
    const contractItem = contract.items.find((item) => item.id === 'SRC-CI-001');
    blocked.status = 'pending_external';
    delete blocked.evidence;
    blocked.required_evidence = [...contractItem.required_evidence];
    const { manifestPath, contractManifestPath } = await writeReadinessInputs(dir, {
      manifest,
      contract,
    });
    const diagnostics = await buildFailureDiagnostics({
      argv: ['--manifest', manifestPath, '--contract-manifest', contractManifestPath],
      env: {},
      pathReportBuilder: readyPathReportBuilder,
    });

    assert.match(diagnostics, /staging evidence blockers still present: SRC-CI-001/);
    assert.match(diagnostics, /pending_external=1/);
    assert.match(diagnostics, /strict_staging_path_ready=yes, strict_release_ready=no/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('buildFailureDiagnostics reports diagnostic load failures', async () => {
  const diagnostics = await buildFailureDiagnostics({
    argv: ['--manifest', 'missing-manifest.json', '--contract-manifest', 'missing-contract.json'],
    env: {},
    pathReportBuilder: readyPathReportBuilder,
  });
  assert.match(diagnostics, /staging evidence blocker diagnostics unavailable:/);
});

test('verifyProductionReadiness accepts strict manifest on clean synced HEAD', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir);
    const result = await verifyProductionReadiness({
      manifestPath,
      localGateReportPath,
      contractManifestPath,
      obsidianNotePath,
      cwd: dir,
      git: fakeGit({
        status: '## main...origin/main\n',
        head: sha,
      }),
      pathReportBuilder: readyPathReportBuilder,
    });

    assert.equal(result.releaseCandidate, sha);
    assert.equal(result.evidenceItems, requiredIds.length);
    assert.equal(result.localGates, gateDefinitions.length);
    assert.equal(result.stagingPathCommands, 13);
    assert.deepEqual(result.proofMarkers, productionReadinessProofMarkers);
    assert.ok(result.proofMarkers.includes('git_remote_tracking_refreshed=true'));
    assert.ok(result.proofMarkers.includes('local_gate_branch_matches_current=true'));
    assert.ok(result.proofMarkers.includes('local_gate_upstream_matches_current=true'));
    assert.ok(result.proofMarkers.includes('local_gate_freshness_checked=true'));
    assert.ok(result.proofMarkers.includes('staging_gap_report_footer_contract_validated=true'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects accepted-risk waivers for final claims', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifest = strictManifest(sha);
    const signoff = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
    signoff.status = 'accepted_risk';
    delete signoff.evidence;
    signoff.decision_ref = 'security/dependency_risk_register.md#DRR-001';
    signoff.owner = 'security';
    signoff.accepted_by = 'release-owner';
    signoff.review_due_at = '2026-07-25';
    signoff.expires_at = '2026-08-25';
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, { manifest });

    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /production readiness claim requires zero accepted-risk items; found 1/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects dirty worktree', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir);
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n M README.md\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
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
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir);
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main [ahead 1]\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /must not be ahead/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects unrefreshable git remote metadata', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir);
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
          fetchError: new Error('remote unavailable'),
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /git fetch --dry-run must succeed before production readiness claim: remote unavailable/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects manifest SHA drift', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      manifest: strictManifest('fedcba9876543210fedcba9876543210fedcba98'),
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /release_candidate must equal current git HEAD SHA/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects local environment manifests', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifest = strictManifest(sha);
    manifest.environment = 'local';
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      manifest,
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /strict release manifest environment must be staging, production, or prod/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness reports strict evidence blocker details', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifest = strictManifest(sha);
    const aiItem = manifest.items.find((item) => item.id === 'EXT-AI-001');
    aiItem.evidence[0].result_summary = aiItem.evidence[0].result_summary.replace(
      'ai-provider-config staging artifact',
      'ai-provider-config',
    );
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      manifest,
    });

    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /STAGING-EVIDENCE-STRICT-VALIDATION .*EXT-AI-001 strict release evidence must include AI markers on ai-provider-config/s,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects local gate report SHA drift', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      localGates: localGateReport({
        gitHead: 'fedcba9876543210fedcba9876543210fedcba98',
      }),
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /local gate report git_head must equal current git HEAD SHA/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects local gate report branch drift', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      localGates: localGateReport({ gitBranch: 'release/candidate', gitUpstream: 'origin/release/candidate' }),
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /local gate report git_branch must equal current git branch/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects local gate report upstream drift', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      localGates: localGateReport({ gitUpstream: 'origin/other-main' }),
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /local gate report git_upstream must equal current git upstream/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects local gate reports older than the staging manifest', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      localGates: localGateReport({ observedAt: '2026-06-25T12:00:00Z' }),
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /local gate report observed_at .* must be at or after staging manifest generated_at/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects stale same-SHA local gate reports', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const verificationTime = '2026-06-27T00:00:00Z';
    const staleObservedAt = new Date(Date.parse(verificationTime) - maxLocalGateReportAgeMs - 1000)
      .toISOString()
      .replace(/\.\d{3}Z$/, 'Z');
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      localGates: localGateReport({ observedAt: staleObservedAt }),
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
        now: verificationTime,
      }),
      /local gate report observed_at .* must be within 24 hours/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects missing local gate report', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifestPath = join(dir, 'manifest.json');
    const contractManifestPath = join(dir, 'contract.json');
    const obsidianNotePath = join(dir, 'obsidian.md');
    await writeFile(manifestPath, JSON.stringify(strictManifest(sha)), 'utf8');
    await writeFile(contractManifestPath, JSON.stringify(contractManifest()), 'utf8');
    await writeFile(obsidianNotePath, '# Production Readiness\n', 'utf8');
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath: join(dir, 'missing-local-gates.json'),
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
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
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      localGates: localGateReport({ dryRun: true }),
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /dry-run reports cannot satisfy local gate evidence/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects stale local gate gap-report footer contract', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const localGates = localGateReport();
    const gapReportGate = localGates.results.find((result) => result.id === 'staging-evidence-gap-report');
    assert.ok(gapReportGate);
    gapReportGate.stdout_tail = gapReportGate.stdout_tail
      .replace(/, blocking_item_ids=SRC-CI-001, counts=[^,]+, proof_markers=/, ', proof_markers=');
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      localGates,
    });
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /staging-evidence-gap-report output must include blocking item IDs in the proof footer/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects missing strict staging PATH tools', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir);
    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: missingStrictPathReportBuilder,
      }),
      /strict staging PATH readiness must pass.*psql.*install PostgreSQL client.*aws.*install AWS CLI v2/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects stale Obsidian readiness snapshot', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir);
    await writeFile(
      obsidianNotePath,
      [
        '# Production Readiness',
        '',
        '<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-START -->',
        '- strict_release_ready: stale',
        '<!-- OBSIDIAN-STAGING-EVIDENCE-SNAPSHOT-END -->',
        '',
      ].join('\n'),
      'utf8',
    );

    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /Obsidian readiness snapshot is stale/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('verifyProductionReadiness rejects stale staging evidence contract through gap report', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'scriptureforge-readiness-'));
  try {
    const manifest = strictManifest(sha);
    const blocked = manifest.items.find((item) => item.id === 'SRC-CI-001');
    blocked.status = 'pending_external';
    delete blocked.evidence;
    blocked.required_evidence = ['old CI proof contract'];
    const contract = contractManifest();
    const contractItem = contract.items.find((item) => item.id === 'SRC-CI-001');
    contractItem.required_evidence = ['new CI proof contract'];
    const { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath } = await writeReadinessInputs(dir, {
      manifest,
      contract,
    });

    await assert.rejects(
      () => verifyProductionReadiness({
        manifestPath,
        localGateReportPath,
        contractManifestPath,
        obsidianNotePath,
        cwd: dir,
        git: fakeGit({
          status: '## main...origin/main\n',
          head: sha,
        }),
        pathReportBuilder: readyPathReportBuilder,
      }),
      /staging evidence gap report must be clear.*STAGING-EVIDENCE-CONTRACT/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

async function writeReadinessInputs(dir, { manifest = strictManifest(sha), localGates = localGateReport(), contract = contractManifest() } = {}) {
  const manifestPath = join(dir, 'manifest.json');
  const localGateReportPath = join(dir, 'local-gates.json');
  const contractManifestPath = join(dir, 'contract.json');
  const obsidianNotePath = join(dir, 'obsidian.md');
  await writeFile(manifestPath, JSON.stringify(manifest), 'utf8');
  await writeFile(localGateReportPath, JSON.stringify(localGates), 'utf8');
  await writeFile(contractManifestPath, JSON.stringify(contract), 'utf8');
  await writeFile(obsidianNotePath, '# Production Readiness\n', 'utf8');
  await syncObsidianReadiness({
    manifestPath,
    contractManifestPath,
    notePath: obsidianNotePath,
    expectedReleaseCandidate: manifest.release_candidate,
    apply: true,
    pathReportBuilder: readyPathReportBuilder,
  });
  return { manifestPath, localGateReportPath, contractManifestPath, obsidianNotePath };
}
function fakeGit({ status, head, fetchError = null }) {
  return (args) => {
    if (args.join(' ') === 'fetch --dry-run') {
      if (fetchError) {
        throw fetchError;
      }
      return '';
    }
    if (args.join(' ') === 'status --porcelain=v1 --branch') {
      return status;
    }
    if (args.join(' ') === 'rev-parse HEAD') {
      return `${head}\n`;
    }
    throw new Error(`unexpected git args ${args.join(' ')}`);
  };
}

function readyPathReportBuilder({ strictStaging } = {}) {
  return pathReport({
    mode: strictStaging ? 'staging-evidence' : 'local',
    missing: new Set(),
  });
}

function missingStrictPathReportBuilder({ strictStaging } = {}) {
  return pathReport({
    mode: strictStaging ? 'staging-evidence' : 'local',
    missing: new Set(['aws', 'psql']),
  });
}

function pathReport({ mode, missing }) {
  const requiredNames = ['rtk', 'git', 'go', 'node', 'npm', 'cargo', 'rustc', 'terraform'];
  const strictNames = ['gopls', 'psql', 'kubectl', 'aws', 'gh'];
  const optionalNames = ['gopls', 'protoc', 'psql', 'kubectl', 'aws', 'gh'];
  return {
    schema_version: 1,
    mode,
    threshold_pass: [...requiredNames, ...strictNames].every((name) => !missing.has(name)),
    required: requiredNames.map((name) => ({
      name,
      required: true,
      ok: !missing.has(name),
      paths: missing.has(name) ? [] : [`C:\\tools\\${name}.exe`],
      version: missing.has(name) ? null : `${name} test-version`,
    })),
    optional: optionalNames.map((name) => ({
      name,
      required: strictNames.includes(name),
      strict: strictNames.includes(name),
      ok: !missing.has(name),
      paths: missing.has(name) ? [] : [`C:\\tools\\${name}.exe`],
      reason: `${name} test reason`,
      remediation: name === 'aws'
        ? 'install AWS CLI v2'
        : name === 'psql'
          ? 'install PostgreSQL client'
          : undefined,
    })),
  };
}

function localGateReport({ dryRun = false, gitHead = sha, gitBranch = 'main', gitUpstream = 'origin/main', observedAt = '2026-06-26T00:05:00Z' } = {}) {
  return {
    schema_version: 1,
    git_head: gitHead,
    git_branch: gitBranch,
    git_upstream: gitUpstream,
    git_ahead: 0,
    git_behind: 0,
    git_remote_refreshed: true,
    git_status_clean: true,
    git_status_short: '',
    observed_at: observedAt,
    duration_ms: 100,
    threshold_pass: true,
    dry_run: dryRun,
    gates_total: gateDefinitions.length,
    gates_run: gateDefinitions.length,
    gates_failed: 0,
    results: gateDefinitions.map((gate, index) => ({
      id: gate.id,
      command: testCommandDisplay(gate),
      cwd: gate.cwd ?? '.',
      skipped: dryRun,
      exit_code: 0,
      duration_ms: index,
      stdout_tail: stdoutForGate(gate.id),
      stderr_tail: '',
    })),
  };
}

function testCommandDisplay(gate) {
  const prefix = gate.cwd ? `(cd ${gate.cwd}) ` : '';
  const envPrefix = gate.env
    ? `${Object.entries(gate.env).map(([key, value]) => `${key}=${value}`).join(' ')} `
    : '';
  return `${prefix}${envPrefix}${gate.command.join(' ')}`;
}

function stdoutForGate(id) {
  if (id === 'project-path-readiness') {
    return [
      'ScriptureForgeAI PATH readiness',
      'mode: local',
      `path readiness proof: ${projectPathProofMarkers.join(', ')}`,
    ].join('\n');
  }
  if (id === 'strict-staging-path-readiness') {
    return [
      'ScriptureForgeAI PATH readiness',
      'mode: staging-evidence',
      `path readiness proof: ${strictStagingPathProofMarkers.join(', ')}`,
    ].join('\n');
  }
  if (id === 'go-test') return `go-test-gate validated: ${goTestProofMarkers.join(', ')}`;
  if (id === 'go-vet') return `go-vet-gate validated: ${goVetProofMarkers.join(', ')}`;
  if (id === 'rls-db-integration') return `rls-db-integration proof: ${rlsDBProofMarkers.join(', ')}`;
  if (id === 'evidence-probes') return `production evidence probe tests validated: ${goProbeProofMarkers.join(', ')}`;
  if (id === 'web-audit' || id === 'mobile-audit') return `npm audit gate validated: ${npmAuditCompletedMarkers.join(', ')}`;
  if (id === 'web-smoke') {
    return [
      'web api smoke proof:',
      'web crypto smoke proof:',
      ...webSmokeProofMarkers,
    ].join('\n');
  }
  if (id === 'web-typecheck') return `web-typecheck-gate validated: ${webTypecheckProofMarkers.join(', ')}`;
  if (id === 'web-build') return `web-build-gate validated: ${webBuildProofMarkers.join(', ')}`;
  if (id === 'mobile-smoke') {
    return [
      'mobile api smoke proof:',
      'mobile crypto smoke proof:',
      ...mobileSmokeProofMarkers,
    ].join('\n');
  }
  if (id === 'mobile-build-check') {
    return [
      `mobile-build-check-gate validated: ${mobileBuildCheckProofMarkers.join(', ')}`,
      `journal crypto verification passed: ${journalCryptoProofMarkers.join(', ')}`,
    ].join('\n');
  }
  if (id === 'rust-protobuf-validation') return `Rust protobuf tooling verified: ${rustProtobufProofMarkers.join(', ')}`;
  if (id === 'rust-cargo-test') {
    return rustCargoProofMarkers.join('\n');
  }
  if (id === 'terraform-fmt') return `terraform-fmt-gate validated: ${terraformFmtProofMarkers.join(', ')}`;
  if (id === 'terraform-init-validate') return `terraform init gate validated: ${terraformInitProofMarkers.join(', ')}`;
  if (id === 'terraform-validate') {
    return [
      'Success! The configuration is valid.',
      `terraform-validate-gate validated: ${terraformValidateProofMarkers.join(', ')}`,
    ].join('\n');
  }
  if (id === 'deployment-skeleton-validation') return `deployment skeleton and runtime config invariants validated: ${deploymentSkeletonProofMarkers.join(', ')}`;
  if (id === 'observability-validation') return `observability artifacts validated: ${observabilityProofMarkers.join(', ')}`;
  if (id === 'journal-crypto-validation') return `journal crypto verification passed: ${journalCryptoProofMarkers.join(', ')}`;
  if (id === 'security-artifacts-validation') return `security artifacts validated: ${securityArtifactsProofMarkers.join(', ')}`;
  if (id === 'dependency-risk-validation') return `dependency risk validated: uuid 7.0.3, expo 56.0.12, DRR-001 required=true, ${dependencyRiskProofMarkers.join(', ')}`;
  if (id === 'secret-hygiene-validation') return `secret hygiene validated across 500 text files: ${secretHygieneProofMarkers.join(', ')}`;
  if (id === 'ci-workflow-validation') return `CI workflow validated: .github/workflows/security.yml (${ciWorkflowRequiredMarkers.length} required markers): ${ciWorkflowProofMarkers.join(', ')}`;
  if (id === 'ci-evidence-gate-validation') return `CI evidence gate markers validated across ${gateDefinitions.length + 1} required entries and ${ciReleaseEvidenceProofMarkers.length + 1} proof markers: ${ciEvidenceGateProofMarkers.join(', ')}`;
  if (id === 'staging-evidence-contract-check') return `Staging evidence contract is in sync: production-readiness/staging-evidence.staging.json: ${stagingEvidenceContractProofMarkers.join(', ')}`;
  if (id === 'staging-evidence-validation') return `staging evidence manifest validated: production-readiness/staging-evidence.example.json (21 items): ${stagingEvidenceProofMarkers.join(', ')}`;
  if (id === 'staging-evidence-gap-report') {
    return [
      'staging evidence gaps for staging (0123456789abcdef0123456789abcdef01234567)',
      'strict release ready: no',
      `proof markers: ${stagingEvidenceGapReportProofMarkers.join(', ')}`,
      'blocking items:',
      '- SRC-CI-001 [pending_external] Clean pushed GitHub Actions run for the exact release SHA.',
      '  required: uploaded ci-release-evidence artifact for SRC-CI-001',
      `gap report proof footer: strict_release_ready=no, strict_staging_path_ready=yes, blocking_items=1, blocking_item_ids=SRC-CI-001, counts=passed:20|pending_external:1|blocked:0|failed:0|accepted_risk:0|non_manifest:0, proof_markers=${stagingEvidenceGapReportProofMarkers.join(', ')}`,
    ].join('\n');
  }
  if (id === 'obsidian-readiness-snapshot-check') return `Obsidian readiness snapshot is in sync: production-readiness/obsidian-production-readiness.md: ${obsidianReadinessProofMarkers.join(', ')}`;
  return '';
}

function strictManifest(releaseCandidate) {
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: releaseCandidate,
    generated_at: '2026-06-25T23:59:00Z',
    items: requiredIds.map((id) => ({
      id,
      category: 'test',
      status: 'passed',
      description: `${id} proof`,
      evidence: [
        passedEvidenceFor(id, releaseCandidate),
      ],
    })),
  };
}

function contractManifest() {
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: sha,
    generated_at: '2026-06-25T23:58:00Z',
    items: requiredIds.map((id) => ({
      id,
      category: 'test',
      status: 'pending_external',
      description: `${id} pending proof`,
      required_evidence: pendingEvidenceFor(id),
    })),
  };
}

function pendingEvidenceFor(id) {
  if (id !== 'SEC-SIGNOFF-001') {
    return [`${id} required evidence`];
  }
  return [
    'Owner/security approval record captured as a content-verified repo security/*.md signoff/approval document or HTTPS non-local approval artifact',
    'Release risk signoff record captured as a content-verified repo security/*.md signoff/approval document or HTTPS non-local approval artifact',
    'record-staging-evidence SEC-SIGNOFF-001 summary markers: threat model approval, security/dependency_risk_register.md#DRR-001, dependency risk decision, residual risk review, owner/security approval, release risk signoff, signoff_artifact_verified=true, and exact release_candidate=<manifest release_candidate>',
  ];
}

function passedEvidenceFor(id, releaseCandidate = sha) {
  const probeById = {
    'SRC-CI-001': 'ciprobe',
    'DEPLOY-TF-001': 'deploymentprobe',
    'DEPLOY-TLS-001': 'stagingprobe',
    'DEPLOY-K8S-001': 'deploymentprobe',
    'SEC-SECRETS-001': 'securityprobe',
    'SEC-DBUSER-001': 'securityprobe',
    'ABUSE-LIMIT-001': 'abuseprobe',
    'DATA-RLS-001': 'tenantprobe',
    'DATA-REDIS-001': 'loadtest',
    'RUST-GRPC-001': 'rustprobe',
    'OBS-OTEL-001': 'observabilityprobe',
    'OBS-ALERT-001': 'observabilityprobe',
    'CLIENT-WEB-001': 'stagingprobe',
    'CLIENT-MOBILE-001': 'mobileprobe',
    'EXT-ZOOM-001': 'zoomprobe',
    'EXT-AI-001': 'aiprobe',
    'PERF-HTTP-001': 'loadtest',
    'PERF-WS-001': 'loadtest',
    'DR-ROLLBACK-001': 'resilienceprobe',
    'DR-BACKUP-001': 'resilienceprobe',
  };
  const probe = probeById[id] ?? 'probe';
  return {
    observed_at: '2026-06-25T12:00:00Z',
    command_or_probe: id === 'SRC-CI-001'
      ? 'go run ./tools/ciprobe -run-artifact-url https://artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt'
      : id === 'SEC-SIGNOFF-001'
        ? 'record-staging-evidence SEC-SIGNOFF-001 --artifact security/release-risk-signoff.md'
        : `go run ./tools/${probe}`,
    artifact: id === 'SEC-SIGNOFF-001'
      ? 'security/release-risk-signoff.md'
      : `https://artifacts.staging.scriptureforge.ai/${probe}.json`,
    result_summary: strictEvidenceSummary(id, releaseCandidate),
    ...(id === 'ABUSE-LIMIT-001' ? { structured_report: abuseRateLimitStructuredReport() } : {}),
    ...(id === 'DATA-RLS-001' ? { structured_report: tenantRLSStructuredReport() } : {}),
    ...(id === 'RUST-GRPC-001' ? { structured_report: rustGRPCRuntimeStructuredReport() } : {}),
    ...(id === 'CLIENT-MOBILE-001' ? { structured_report: mobileNativeCryptoStructuredReport() } : {}),
    ...(id === 'EXT-AI-001' ? { structured_report: aiGenerationAuditStructuredReport() } : {}),
    ...(id === 'EXT-ZOOM-001' ? { structured_report: zoomResilienceWebhookStructuredReport() } : {}),
    ...(id === 'OBS-OTEL-001' ? { structured_report: observabilityOTELStructuredReport(releaseCandidate) } : {}),
    ...(id === 'OBS-ALERT-001' ? { structured_report: observabilityAlertStructuredReport(releaseCandidate) } : {}),
    ...(id === 'DR-ROLLBACK-001' ? { structured_report: rollbackDegradationStructuredReport(releaseCandidate) } : {}),
    ...(id === 'DR-BACKUP-001' ? { structured_report: backupRestoreStructuredReport(releaseCandidate) } : {}),
    ...(id === 'PERF-HTTP-001' ? { structured_report: httpLoadThresholdStructuredReport() } : {}),
    ...(['PERF-WS-001', 'DATA-REDIS-001'].includes(id) ? { structured_report: websocketRedisSequenceStructuredReport() } : {}),
  };
}

function strictEvidenceSummary(id, releaseCandidate = sha) {
  if (id === 'SRC-CI-001') {
    return `github-actions-release-run passed with uploaded ci-release-evidence artifact release_candidate=${releaseCandidate} proof markers: ${ciReleaseEvidenceProofMarkers.join(', ')}`;
  }
  if (id === 'DEPLOY-TF-001') {
    return `DEPLOY-TF-001 deploymentprobe passed: terraform-remote-backend-init staging artifact terraform s3 backend bucket key encrypt=true kms_key_id=alias/scriptureforge-tf-state versioning=enabled dynamodb_table successfully initialized release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; terraform-staging-plan staging artifact Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111 database_kms_key_arn=arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222 redis_kms_key_arn=arn:aws:kms:us-east-1:123456789012:key/33333333-3333-4333-8333-333333333333 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; terraform-staging-apply-or-approval staging artifact deployment approval approved DEPLOY-TF-001 change_ticket=PLATFORM-123 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123 distinct_terraform_artifacts=true`;
  }
  if (id === 'DEPLOY-TLS-001') {
    const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
    return [
      'DEPLOY-TLS-001 stagingprobe passed: api-live /live HTTP 200',
      'api-ready /ready HTTP 200',
      'api-tls TLS certificate cert_not_after cert_hostname=api.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
      'api-http-redirect HTTP HTTPS redirect',
      'web-root web root HTTP 200',
      'web-tls TLS certificate cert_not_after cert_hostname=app.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
      'web-http-redirect HTTP HTTPS redirect',
      'ssl-labs-a-plus staging artifact SSL Labs grade=A+ ssl_labs_grade=A+ api_hostname=api.staging.scriptureforge.ai web_hostname=app.staging.scriptureforge.ai',
    ].map((segment) => `${segment} ${release}`).join('; ');
  }
  if (id === 'DEPLOY-K8S-001') {
    return `DEPLOY-K8S-001 deploymentprobe passed: kubernetes-rollout-status staging artifact namespace staging deployment scriptureforge-api scriptureforge-web scriptureforge-rust-engine successfully rolled out ready available release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; kubernetes-workload-resources staging artifact namespace staging deployment service ingress hpa pdb ready available targets minavailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123 scriptureforge-api scriptureforge-web scriptureforge-rust-engine concrete_image_digests=3 workload_image_digests=3 distinct_kubernetes_artifacts=true`;
  }
  if (id === 'EXT-ZOOM-001') {
  return `EXT-ZOOM-001 zoomprobe passed: zoom-oauth-readiness staging artifact oauth account_credentials status ok release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; zoom-meeting-create-or-fallback staging artifact meeting join_url zoom.us release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; zoom-timeout-circuit-fallback staging artifact timeout provider timeout circuit open circuit_open_fallback fallback offline://in-person provider_timeout=true circuit_open=true offline_fallback=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; zoom-webhook-signature-delivery staging artifact webhook signature x-zm-signature=v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa x-zm-request-timestamp=1710000000 stale replay 401 invalid signed 200 stale_rejected=true replay_rejected=true invalid_signature_rejected=true signed_delivery_accepted=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; zoom-webhook-url-validation staging artifact endpoint.url_validation plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; zoom-duplicate-webhook-idempotency staging artifact duplicate x-zm-trackingid=zm-track-123 delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects single_state_mutation=true no_duplicate_side_effects=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; zoom-meeting-room-mapping staging artifact meeting_external_id=zoom-123 live_rooms internal_room_id=room-abc redis room state mapped unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
}
  if (id === 'EXT-AI-001') {
    return `EXT-AI-001 aiprobe passed: ai-provider-config staging artifact AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted configured AI_PROVIDER=openai AI_CHAT_MODEL=gpt-staging AI_CHAT_ENDPOINT=https://api.openai.com/v1/chat/completions AI_HTTP_TIMEOUT_MS=3500 AI_MAX_RETRIES=1 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; ai-generation-route staging artifact /api/v1/ai/generate/study authenticated JWT claims organization_id=org-staging user_id=user-staging request_id=req-1 200 generated_curriculum [Genesis 1:1] release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; ai-timeout-degradation staging artifact provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT provider_timeout=true retry_exhausted=true fail_closed=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; ai-citation-verification staging artifact no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-1 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-1 citation_id=cite-1 succeeded failed verified tenant rls cross-tenant hidden distinct_ai_artifacts=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  }
  if (id === 'OBS-OTEL-001') {
    return `OBS-OTEL-001 observabilityprobe passed: collector-otlp-config staging artifact receivers otlp 4317 4318 exporters service release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; api-prometheus-metrics staging artifact scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum scriptureforge_http_requests_total{ status= websocket_active_connections_count scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped" ai_inference_duration_seconds_sum ai_inference_duration_seconds_count scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success" scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success" api_metrics_samples_positive=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; rust-prometheus-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total scriptureforge_rust_engine_embedding_failures_total scriptureforge_rust_engine_vector_search_requests_total scriptureforge_rust_engine_vector_search_failures_total rust_metrics_samples_positive=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; trace-backend-search staging artifact scriptureforge-api scriptureforge-rust-engine trace_id=0123456789abcdef0123456789abcdef route=/api/v1/ai/generate/study method=POST release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; log-backend-trace-correlation staging artifact trace_id=0123456789abcdef0123456789abcdef scriptureforge-api scriptureforge-rust-engine route=/api/v1/ai/generate/study method=POST timestamp=2026-07-01T12:00:00Z severity=info service_version deployment_environment tenant_id=org-staging user_id=user-staging role=admin distinct_otel_artifacts=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  }
  if (id === 'OBS-ALERT-001') {
    return `OBS-ALERT-001 observabilityprobe passed: dashboard-import staging artifact ScriptureForge scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; alert-rules-loaded staging artifact ScriptureForgeHighErrorRate ScriptureForgeTrafficAbsent ScriptureForgeAuthFailureSpike ScriptureForgeAbuseLimitSpike ScriptureForgeRouteLatencyElevated ScriptureForgeDependencyFailures ScriptureForgeAIInferenceLatencyElevated ScriptureForgeJournalWriteFailures ScriptureForgeRoomStreamFailures ScriptureForgeRoomBroadcastDrops ScriptureForgeRustEngineFailures scriptureforge_http_requests_total scriptureforge_dependency_operations_total ai_inference_duration_seconds release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; alert-delivery-status staging artifact success alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123 delivered test alert alertmanager release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; telemetry-retention-policy staging artifact retention 30 days trace logs metrics distinct_alert_artifacts=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  }
  if (id === 'RUST-GRPC-001') {
    const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-rust-engine:${releaseCandidate} deployment_environment=staging load_run_id=load-run-123`;
    return [
      'RUST-GRPC-001 rustprobe passed: rust-grpc-health staging artifact grpc health scriptureforge.engine.ScriptureEngine SERVING',
      'rust-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total scriptureforge_rust_engine_embedding_failures_total scriptureforge_rust_engine_vector_search_requests_total scriptureforge_rust_engine_vector_search_failures_total Prometheus metrics rust_metrics_samples_verified=true rust_embedding_requests_positive=true rust_vector_search_requests_positive=true embedding_requests=1 vector_search_requests=1',
      'api-rust-integration-metrics staging artifact Go API rust_engine vector_search success scriptureforge_dependency_operations_total scriptureforge_dependency_operation_duration_seconds_sum api_rust_metrics_samples_verified=true distinct_metrics_targets=true api_rust_vector_search_ops=1 api_rust_vector_search_seconds=0.042',
    ].map((segment) => `${segment} ${release}`).join('; ');
  }
  if (id === 'CLIENT-MOBILE-001') {
    const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-mobile:${releaseCandidate} load_run_id=load-run-123`;
    return [
      'CLIENT-MOBILE-001 mobileprobe passed: mobile-eas-or-device-run staging artifact eas build finished android ios native device installed app release channel staging expo profile staging mobile_build_id=mobile-build-123 platforms=android,ios release_channel=staging expo_profile=staging distinct_mobile_artifacts=true',
      'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-123 device_os=ios device_model=iphone15pro app_runtime=installed-staging-app installed staging app runtime AES-GCM round-trip aes_gcm_roundtrip=true unique_iv=true unique IV tamper rejected tamper_rejected=true associated data wrong associated data rejected associated_data_rejected=true associated_data_salt_id=journal:self-test:server-derived-salt associated_data_salt_version=1 non-extractable provider-bound key fallback-derived key rejected key disposed key_disposed=true disposed handle rejected disposed_handle_rejected=true revoked_key_rejected=true stale raw key rejected passphrase wiped passphrase buffer zeroized passphrase_buffer_zeroized=true salt wiped salt buffer zeroized salt_buffer_zeroized=true plaintext cleared plaintext buffer zeroized plaintext_buffer_zeroized=true distinct_mobile_artifacts=true',
      'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL EXPO_PUBLIC_WS_BASE_URL EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging mobile_build_id=mobile-build-123 https:// wss:// staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.scriptureforge.ai EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.scriptureforge.ai distinct_mobile_artifacts=true',
    ].map((segment) => `${segment} ${release}`).join('; ');
  }
  if (id === 'CLIENT-WEB-001') {
    return webClientSummary(releaseCandidate);
  }
  if (id === 'DATA-RLS-001') {
    return tenantRLSSummary(releaseCandidate);
  }
  if (id === 'SEC-SECRETS-001') {
    const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
    return `SEC-SECRETS-001 securityprobe passed: irsa-service-account staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity ${release}; secret-provider-class staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN ${release}; synced-secret-metadata-redacted staging artifact namespace=staging scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true ${release}; iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources ${release}; scoped-secrets-access-test staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret denied unscoped secret AccessDenied distinct_secret_artifacts=true ${release}`;
  }
  if (id === 'SEC-DBUSER-001') {
    return `SEC-DBUSER-001 securityprobe passed: database-scoped-user staging artifact connected as scriptureforge_app current_user=scriptureforge_app superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails app_grants=SELECT,INSERT,UPDATE,DELETE release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  }
  if (id === 'DR-ROLLBACK-001') {
    return `DR-ROLLBACK-001 resilienceprobe passed: api-ready-before-rollback staging artifact ready service_version deployment_environment pre_rollback_version pre_rollback_version=release-1 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; rollback-rollout-artifact staging artifact rollout undo revision previous_revision target_revision scriptureforge-api successfully rolled out release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; api-ready-after-rollback staging artifact ready service_version deployment_environment post_rollback_version post_rollback_version=release-0 rolled_back_from rolled_back_from=release-1 rolled_back_to rolled_back_to=release-0 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; degradation-drill-artifact staging artifact AI Zoom degradation fallback AI_ORCHESTRATION_ENGINE_FAULT offline://in-person non-AI routes healthy zoom circuit open ai_fault=true zoom_offline_fallback=true non_ai_routes_healthy=true zoom_circuit_open=true distinct_rollback_artifacts=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  }
  if (id === 'DR-BACKUP-001') {
    return `DR-BACKUP-001 resilienceprobe passed: backup-snapshot-artifact staging artifact snapshot snapshot_id=snap-123 available encrypted kms_key_id=arn:aws:kms:us-east-1:123456789012:key/44444444-4444-4444-8444-444444444444 retention automated backup source cluster rpo_minutes=15 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; restore-drill-artifact staging artifact restore restore_job_id=restore-456 available staging restored endpoint source snapshot_id=snap-123 checksum isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123; restored-database-smoke staging artifact smoke passed restored database tenant journal auth RLS migration version no plaintext journal distinct_backup_artifacts=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  }
  if (id === 'ABUSE-LIMIT-001') {
    const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
    return [
      'ABUSE-LIMIT-001 abuseprobe passed: auth-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'auth-account-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 account-scoped login account_scoped=true rotating forwarded client IP forwarded_client_ip_rotated=true',
      'auth-refresh-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 refresh token refresh_token_scoped=true',
      'ai-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'journal-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'rooms-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'websocket-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 websocket upgrade websocket_upgrade=true',
      'config_artifact_verified=true',
      'config_artifact_summary ABUSE_LIMIT_AUTH_REQUESTS=2 ABUSE_LIMIT_AUTH_WINDOW_SECONDS=60 ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=2 ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=60 ABUSE_LIMIT_AI_REQUESTS=2 ABUSE_LIMIT_JOURNAL_REQUESTS=2 ABUSE_LIMIT_ROOMS_REQUESTS=2 ABUSE_LIMIT_WEBSOCKET_REQUESTS=2 ABUSE_LIMIT_MAX_BUCKETS=1000 TRUST_PROXY_HEADERS=true X-Forwarded-For X-Real-IP redacted distinct_abuse_artifacts=true',
    ].map((segment) => `${segment} ${release}`).join('; ');
  }
  if (id === 'PERF-HTTP-001') {
    return `PERF-HTTP-001 staging artifact profile=staging_http https://api.staging.scriptureforge.ai min_rps=5000 max_p99_ms=200 production_target_rps=5000 production_target_p99_ms=200 production_min_duration_ms=60000 duration_ms=60000 duration_ms>=60000 observed_rps=5200 observed_p99_ms=180 threshold_pass=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123 http_replica_artifact_url=https://artifacts.staging.scriptureforge.ai/load/http-replicas.txt http_replica_artifact_verified http_replica_count=2 dependency_telemetry_artifact_url=https://artifacts.staging.scriptureforge.ai/load/dependency-telemetry.txt dependency_telemetry_artifact_verified dependency_latency_artifact_verified=true dependency_postgres_p99_ms=120 dependency_redis_p99_ms=20; verified markers: http_replica_artifact_verified, dependency_telemetry_artifact_verified, dependency_latency_artifact_verified=true, http_distinct_artifacts=true`;
  }
  if (id === 'PERF-WS-001') {
    return `PERF-WS-001 staging artifact profile=staging_websocket min_rps=500 max_p99_ms=200 production_target_rps=500 production_target_p99_ms=200 production_min_duration_ms=60000 production_min_ws_events=30000 duration_ms=60000 duration_ms>=60000 observed_rps=620 observed_p99_ms=140 ws_expected_events=30000 ws_unique_sequences=30000 ws_min_sequence=1 ws_max_sequence=30000 threshold_pass=true release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123 ws_origin=https://web.staging.scriptureforge.ai ws_room_id=room-1 ws_user_id=user-1 ws_organization_id=org-1 ws_reconnect_room_id=room-1 ws_polling_room_id=room-1 redis_telemetry_room_id=room-1 ws_reconnect_sequence_continues=true ws_authenticated=true ws_polling_latest_sequence=30000 ws_polling_artifact_latest_sequence=30000 ws_sequence_contiguous=true ws_replica_count=2 room_broadcast_drops=0; verified markers: ws_replica_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt, ws_replica_artifact_verified, ws_reconnect_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt, ws_reconnect_artifact_verified, ws_reconnect_sequence_continues=true, ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt, ws_polling_artifact_verified, ws_polling_artifact_latest_sequence_validated=true, ws_polling_artifact_latest_sequence_matches_run=true, redis_telemetry_artifact_url=https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt, redis_telemetry_artifact_verified, ws_distinct_artifacts=true, room_broadcast_drops=0`;
  }
  if (id === 'DATA-REDIS-001') {
    return `DATA-REDIS-001 staging artifact profile=staging_websocket release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123 ws_room_id=room-1 ws_user_id=user-1 ws_organization_id=org-1 ws_reconnect_room_id=room-1 ws_polling_room_id=room-1 redis_telemetry_room_id=room-1 ws_reconnect_sequence_continues=true production_min_ws_events=30000 ws_sequence_contiguous=true ws_expected_events=30000 ws_unique_sequences=30000 ws_min_sequence=1 ws_max_sequence=30000 ws_polling_latest_sequence=30000 ws_polling_artifact_latest_sequence=30000 ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt redis_telemetry_artifact_url=https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt; verified markers: ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt, redis_telemetry_artifact_verified, ws_polling_artifact_latest_sequence_validated=true, ws_polling_artifact_latest_sequence_matches_run=true, ws_distinct_artifacts=true, room_broadcast_drops=0`;
  }
  if (id === 'SEC-SIGNOFF-001') {
    return `threat model approval complete; security/dependency_risk_register.md#DRR-001 dependency risk decision reviewed; residual risk review complete; owner/security approval recorded; release risk signoff approved; signoff_artifact_verified=true; release_candidate=${releaseCandidate}`;
  }
  return `${id} passed`;
}

function tenantRLSSummary(releaseCandidate) {
  const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  const rlsTables = tenantRLSTableNames();
  const rlsTableOutcomes = rlsTables
    .flatMap((table) => [
      `rls_table_${table}_same_visible=true`,
      `rls_table_${table}_cross_hidden=true`,
      `rls_table_${table}_write_denied=true`,
    ])
    .join(' ');
  return [
    'DATA-RLS-001 tenantprobe passed: owner-create-encrypted-journal same-tenant journal write accepted encrypted journal created plaintext not returned plaintext-shaped journal payload denied malformed encrypted envelope rejected journal_id=journal-1',
    'blocked-journal-tenant-override-write-denied cross-tenant journal write denied tenant override rejected',
    'owner-read-created-journal same-tenant journal read visible created journal returned journal_id=journal-1',
    'owner-list-contains-created-journal same-tenant journal list visible created journal present journal_id=journal-1',
    'blocked-read-created-journal cross-tenant journal read denied created journal hidden journal_id=journal-1',
    'blocked-list-excludes-created-journal cross-tenant journal list hidden created journal absent journal_id=journal-1',
    'owner-create-room same-tenant room write accepted room created room_id=room-1',
    'blocked-room-tenant-override-write-denied cross-tenant room write denied tenant override rejected',
    'owner-active-rooms-contains-created-room same-tenant room list visible created room present room_id=room-1',
    'blocked-active-rooms-excludes-created-room cross-tenant room list hidden created room absent room_id=room-1',
    'owner-room-state same-tenant room state visible created room state returned room_id=room-1',
    'blocked-room-state-denied cross-tenant room state denied created room state hidden room_id=room-1',
    `database-rls-context-proof staging artifact current_user=scriptureforge_app non-superuser superuser=false bypassrls=false app.current_org_id app.current_org_id=11111111-1111-4111-8111-111111111111 current_setting('app.current_org_id') blocked_org_id=22222222-2222-4222-8222-222222222222 row_security=on FORCE ROW LEVEL SECURITY rls_tables_verified=9 rls_forced_tables=9 rls_table_names=${rlsTables.join(',')} rls_policy_scope=app.current_org_id ${rlsTables.join(' ')} ${rlsTableOutcomes} same-tenant read visible cross-tenant read hidden cross-tenant write denied auth_refresh_session_rls=true auth_mfa_rls=true workspace_switch_tenant_match=true privileged_mfa_enrollment_rls=true ai_audit_rls=true generated_curriculum_audit_rls=true distinct_db_rls_artifact=true`,
  ].map((segment) => `${segment} ${release}`).join('; ');
}

function tenantRLSStructuredReport() {
  return {
    database_rls_context_proof: {
      owner_org_id: '11111111-1111-4111-8111-111111111111',
      blocked_org_id: '22222222-2222-4222-8222-222222222222',
      created_journal_id: 'journal-1',
      created_room_id: 'room-1',
      application_role: 'scriptureforge_app',
      row_security: 'on',
      rls_tables_verified: 9,
      rls_forced_tables: 9,
      rls_policy_scope: 'app.current_org_id',
      rls_table_names: tenantRLSTableNames(),
      rls_table_outcomes: tenantRLSTableNames().map((table) => ({
        table,
        same_visible: true,
        cross_hidden: true,
        write_denied: true,
      })),
    },
  };
}

function abuseRateLimitStructuredReport() {
  const profileNames = ['auth-rate-limit', 'auth-account-rate-limit', 'auth-refresh-rate-limit', 'ai-rate-limit', 'journal-rate-limit', 'rooms-rate-limit', 'websocket-rate-limit'];
  return {
    abuse_rate_limit_proof: {
      config_artifact_verified: true,
      config_assignments: {
        ABUSE_LIMIT_AUTH_REQUESTS: 2,
        ABUSE_LIMIT_AUTH_WINDOW_SECONDS: 60,
        ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS: 2,
        ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS: 60,
        ABUSE_LIMIT_AI_REQUESTS: 2,
        ABUSE_LIMIT_JOURNAL_REQUESTS: 2,
        ABUSE_LIMIT_ROOMS_REQUESTS: 2,
        ABUSE_LIMIT_WEBSOCKET_REQUESTS: 2,
        ABUSE_LIMIT_MAX_BUCKETS: 1000,
      },
      profiles: profileNames.map((name) => ({
        name,
        attempts: 2,
        retry_after: 60,
        rate_limit: 1,
        rate_limit_remaining: 0,
        rate_limit_reset: 1782403200,
        account_scoped: name === 'auth-account-rate-limit',
        forwarded_client_ip_rotated: name === 'auth-account-rate-limit',
        refresh_token_scoped: name === 'auth-refresh-rate-limit',
        websocket_upgrade: name === 'websocket-rate-limit',
      })),
    },
  };
}

function rustGRPCRuntimeStructuredReport() {
  return {
    rust_grpc_runtime_proof: {
      deployment_environment: 'staging',
      grpc_target: 'scriptureforge-rust-engine.staging.svc.cluster.local:50051',
      metrics_target: 'https://rust-metrics.staging.scriptureforge.ai/metrics',
      api_metrics_target: 'https://api.staging.scriptureforge.ai/metrics',
      load_run_id: 'load-run-123',
      health_status: 'SERVING',
      service_name: 'scriptureforge.engine.ScriptureEngine',
      embedding_requests: 1,
      vector_search_requests: 1,
      api_rust_vector_search_ops: 1,
      api_rust_vector_search_seconds: 0.042,
    },
  };
}

function mobileNativeCryptoStructuredReport() {
  return {
    mobile_native_crypto_proof: {
      mobile_build_id: 'mobile-build-123',
      load_run_id: 'load-run-123',
      platforms: 'android,ios',
      release_channel: 'staging',
      expo_profile: 'staging',
      provider: 'react-native-quick-crypto',
      native_required: true,
      aes_gcm_roundtrip: true,
      tamper_rejected: true,
      associated_data_rejected: true,
      unique_iv: true,
      key_disposed: true,
      disposed_handle_rejected: true,
      revoked_key_rejected: true,
      passphrase_buffer_zeroized: true,
      salt_buffer_zeroized: true,
      plaintext_buffer_zeroized: true,
      associated_data_salt_id: 'journal:self-test:server-derived-salt',
      associated_data_salt_version: 1,
      device_os: 'ios',
      device_model: 'iphone15pro',
      app_runtime: 'installed-staging-app',
      api_base_url: 'https://api.staging.scriptureforge.ai',
      ws_base_url: 'wss://api.staging.scriptureforge.ai',
      require_native_crypto: true,
      deployment_environment: 'staging',
    },
  };
}

function observabilityOTELStructuredReport(releaseCandidate = sha) {
  return {
    observability_otel_proof: {
      release_candidate: releaseCandidate,
      service_version: `scriptureforge-api:${releaseCandidate}`,
      load_run_id: 'load-run-123',
      trace_id: '0123456789abcdef0123456789abcdef',
      observed_route: '/api/v1/ai/generate/study',
      http_method: 'POST',
      tenant_id: 'org-staging',
      user_id: 'user-staging',
      role: 'admin',
      collector_target: 'https://observability.staging.scriptureforge.ai/collector-otlp-config',
      api_metrics_target: 'https://observability.staging.scriptureforge.ai/api-prometheus-metrics',
      rust_metrics_target: 'https://observability.staging.scriptureforge.ai/rust-prometheus-metrics',
      trace_query_target: 'https://traces.staging.scriptureforge.ai/search?trace_id=0123456789abcdef0123456789abcdef',
      log_query_target: 'https://logs.staging.scriptureforge.ai/search?trace_id=0123456789abcdef0123456789abcdef',
      trace_query_trace_id: '0123456789abcdef0123456789abcdef',
      log_query_trace_id: '0123456789abcdef0123456789abcdef',
      trace_query_route: '/api/v1/ai/generate/study',
      log_query_route: '/api/v1/ai/generate/study',
      trace_query_http_method: 'POST',
      log_query_http_method: 'POST',
      log_tenant_id: 'org-staging',
      log_user_id: 'user-staging',
      log_role: 'admin',
    },
  };
}

function observabilityAlertStructuredReport(releaseCandidate = sha) {
  return {
    observability_alert_proof: {
      release_candidate: releaseCandidate,
      service_version: `scriptureforge-api:${releaseCandidate}`,
      load_run_id: 'load-run-123',
      alert_name: 'ScriptureForgeHighErrorRate',
      alert_receiver: 'staging-release',
      dashboard_target: 'https://observability.staging.scriptureforge.ai/dashboard-import',
      alert_rules_target: 'https://observability.staging.scriptureforge.ai/alert-rules-loaded',
      alert_delivery_target: 'https://observability.staging.scriptureforge.ai/alert-delivery-status',
      retention_target: 'https://observability.staging.scriptureforge.ai/telemetry-retention-policy',
      delivery_alert_name: 'ScriptureForgeHighErrorRate',
      delivery_alert_receiver: 'staging-release',
      delivery_id: 'am-delivery-123',
    },
  };
}

function rollbackDegradationStructuredReport(releaseCandidate = sha) {
  return {
    rollback_degradation_proof: {
      release_candidate: releaseCandidate,
      service_version: `scriptureforge-api:${releaseCandidate}`,
      load_run_id: 'load-run-123',
      before_ready_target: 'https://artifacts.staging.scriptureforge.ai/resilience/api-ready-before-rollback.txt',
      rollout_target: 'https://artifacts.staging.scriptureforge.ai/resilience/rollback-rollout-artifact.txt',
      after_ready_target: 'https://artifacts.staging.scriptureforge.ai/resilience/api-ready-after-rollback.txt',
      degradation_target: 'https://artifacts.staging.scriptureforge.ai/resilience/degradation-drill-artifact.txt',
      pre_rollback_version: 'release-1',
      post_rollback_version: 'release-0',
      rolled_back_from: 'release-1',
      rolled_back_to: 'release-0',
      ai_fault: true,
      zoom_offline_fallback: true,
      non_ai_routes_healthy: true,
      zoom_circuit_open: true,
    },
  };
}

function backupRestoreStructuredReport(releaseCandidate = sha) {
  return {
    backup_restore_proof: {
      release_candidate: releaseCandidate,
      service_version: `scriptureforge-api:${releaseCandidate}`,
      load_run_id: 'load-run-123',
      backup_snapshot_target: 'https://artifacts.staging.scriptureforge.ai/resilience/backup-snapshot-artifact.txt',
      restore_drill_target: 'https://artifacts.staging.scriptureforge.ai/resilience/restore-drill-artifact.txt',
      restored_database_smoke_target: 'https://artifacts.staging.scriptureforge.ai/resilience/restored-database-smoke.txt',
      snapshot_id: 'snap-123',
      kms_key_id: 'arn:aws:kms:us-east-1:123456789012:key/44444444-4444-4444-8444-444444444444',
      rpo_minutes: 15,
      restore_job_id: 'restore-456',
      source_snapshot_id: 'snap-123',
      rto_minutes: 30,
      restore_duration_minutes: 18,
    },
  };
}

function httpLoadThresholdStructuredReport() {
  return {
    http_load_threshold_proof: {
      target: 'https://api.staging.scriptureforge.ai/health',
      load_run_id: 'load-run-123',
      observed_rps: 5200,
      observed_p99_ms: 180,
      duration_ms: 60000,
      production_target_rps: 5000,
      production_target_p99_ms: 200,
      production_min_duration_ms: 60000,
      threshold_pass: true,
      http_replica_count: 2,
      dependency_postgres_p99_ms: 120,
      dependency_redis_p99_ms: 20,
    },
  };
}

function websocketRedisSequenceStructuredReport() {
  return {
    websocket_redis_sequence_proof: {
      target: 'wss://api.staging.scriptureforge.ai/api/v1/rooms/stream/room-1',
      ws_origin: 'https://web.staging.scriptureforge.ai',
      load_run_id: 'load-run-123',
      ws_room_id: 'room-1',
      ws_user_id: 'user-1',
      ws_organization_id: 'org-1',
      ws_reconnect_room_id: 'room-1',
      ws_polling_room_id: 'room-1',
      redis_telemetry_room_id: 'room-1',
      observed_rps: 620,
      observed_p99_ms: 140,
      duration_ms: 60000,
      production_target_rps: 500,
      production_target_p99_ms: 200,
      production_min_duration_ms: 60000,
      production_min_ws_events: 30000,
      ws_expected_events: 30000,
      ws_unique_sequences: 30000,
      ws_min_sequence: 1,
      ws_max_sequence: 30000,
      ws_polling_latest_sequence: 30000,
      ws_polling_artifact_latest_sequence: 30000,
      ws_replica_count: 2,
      room_broadcast_drops: 0,
      threshold_pass: true,
      ws_authenticated: true,
      ws_sequence_contiguous: true,
      ws_reconnect_sequence_continues: true,
    },
  };
}

function aiGenerationAuditStructuredReport() {
  return {
    ai_generation_audit_proof: {
      ai_provider: 'openai',
      ai_chat_model: 'gpt-staging',
      ai_chat_endpoint: 'https://api.openai.com/v1/chat/completions',
      ai_http_timeout_ms: 3500,
      ai_max_retries: 1,
      generation_request_id: 'req-1',
      generation_organization_id: 'org-staging',
      generation_user_id: 'user-staging',
      provider_timeout: true,
      retry_exhausted: true,
      fail_closed: true,
      citation_id: 'cite-1',
      audit_request_id: 'req-1',
      audit_organization_id: 'org-staging',
      audit_user_id: 'user-staging',
      audit_citation_id: 'cite-1',
    },
  };
}

function zoomResilienceWebhookStructuredReport() {
  return {
    zoom_resilience_webhook_proof: {
      provider_timeout: true,
      circuit_open: true,
      offline_fallback: true,
      webhook_signature: 'v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      webhook_timestamp: '1710000000',
      stale_rejected: true,
      replay_rejected: true,
      invalid_signature_rejected: true,
      signed_delivery_accepted: true,
      plain_token: 'zoom-plain-123',
      encrypted_token: 'zoom-encrypted-456',
      validation_response: '200',
      duplicate_delivery_id: 'zm-delivery-123',
      duplicate_tracking_id: 'zm-track-123',
      single_state_mutation: true,
      no_duplicate_side_effects: true,
      meeting_external_id: 'zoom-123',
      internal_room_id: 'room-abc',
    },
  };
}

function tenantRLSTableNames() {
  return [
    'organizations',
    'users',
    'scripture_texts',
    'refresh_tokens',
    'journal_entries',
    'live_rooms',
    'room_participants',
    'ai_request_logs',
    'citation_trails',
  ];
}

function webClientSummary(releaseCandidate) {
  const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-web:${releaseCandidate} load_run_id=load-run-123`;
  return [
    'CLIENT-WEB-001 stagingprobe passed: web-root web root HTTP 200',
    'web-tls TLS certificate cert_not_after cert_hostname=app.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
    'web-http-redirect HTTP HTTPS redirect',
    'web-auth-browser-smoke staging artifact login register authenticated https:// user_id=user-staging organization_id=org-staging distinct_web_artifacts=true',
    'web-journal-browser-smoke staging artifact journal encrypted save load plaintext absent associated data wrong associated data rejected user_id=user-staging organization_id=org-staging journal_id=journal-staging distinct_web_artifacts=true',
    'web-room-browser-smoke staging artifact room create select WebSocket connected user_id=user-staging organization_id=org-staging room_id=room-staging distinct_web_artifacts=true',
  ].map((segment) => `${segment} ${release}`).join('; ');
}
