import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { validateManifest } from './validate-staging-evidence.mjs';
import { buildPathReport } from './verify-project-path.mjs';

const allowedSignoffAcceptedRiskDecisionRef = 'security/dependency_risk_register.md#DRR-001';

export const stagingEvidenceGapReportProofMarkers = [
  'strict_release_readiness_computed=true',
  'strict_staging_path_readiness_computed=true',
  'release_candidate_match_checked=true',
  'pending_external_items_counted=true',
  'non_manifest_blockers_counted=true',
  'contract_drift_blockers_counted=true',
  'accepted_risk_status_counted=true',
  'accepted_risk_metadata_freshness_checked=true',
  'strict_release_validation_checked=true',
  'blocking_items_listed=true',
  'blocking_item_required_evidence_listed=true',
];

function usage() {
  return [
    'Usage:',
    '  node tools/report-staging-evidence-gaps.mjs [--manifest <path>] [--contract-manifest <path>] [--format text|json|obsidian] [--expected-release-candidate <sha>] [--allow-blockers]',
    '',
    'Validates a staging evidence manifest and reports the items that still block strict release readiness.',
  ].join('\n');
}

export function parseArgs(argv) {
  const args = {
    manifest: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.staging.json',
    contractManifest: process.env.STAGING_EVIDENCE_CONTRACT_FILE ?? 'production-readiness/staging-evidence.example.json',
    format: 'text',
    expectedReleaseCandidate: process.env.EXPECTED_RELEASE_CANDIDATE,
    allowBlockers: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--manifest') {
      args.manifest = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--contract-manifest') {
      args.contractManifest = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--format') {
      args.format = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--expected-release-candidate') {
      args.expectedReleaseCandidate = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--allow-blockers') {
      args.allowBlockers = true;
    } else {
      throw new Error(`unknown argument ${argv[i]}\n${usage()}`);
    }
  }
  assert.ok(args.manifest, '--manifest must not be empty');
  assert.ok(args.contractManifest, '--contract-manifest must not be empty');
  assert.ok(
    ['text', 'json', 'obsidian'].includes(args.format),
    '--format must be text, json, or obsidian',
  );
  return args;
}

export function summarizeGaps(manifest, { expectedReleaseCandidate, strictPathReport, contractManifest, today = new Date().toISOString().slice(0, 10) } = {}) {
  validateManifest(manifest, { today });
  if (contractManifest) {
    validateManifest(contractManifest, { today });
  }
  const summary = {
    environment: manifest.environment,
    release_candidate: manifest.release_candidate,
    expected_release_candidate: expectedReleaseCandidate ?? null,
    release_candidate_matches_expected: expectedReleaseCandidate ? manifest.release_candidate === expectedReleaseCandidate : null,
    total_items: manifest.items.length,
    passed: 0,
    pending_external: 0,
    blocked: 0,
    failed: 0,
    accepted_risk: 0,
    strict_release_ready: true,
    strict_staging_path_ready: strictPathReport ? strictPathReport.threshold_pass === true : null,
    non_manifest_blockers: 0,
    blocking_items: [],
    proof_markers: stagingEvidenceGapReportProofMarkers,
  };

  if (expectedReleaseCandidate && manifest.release_candidate !== expectedReleaseCandidate) {
    summary.strict_release_ready = false;
    summary.non_manifest_blockers += 1;
    summary.blocking_items.push({
      id: 'RELEASE-CANDIDATE-SHA',
      category: 'source-control-ci',
      status: 'failed',
      description: 'Staging evidence manifest release_candidate does not match the expected release SHA.',
      expected_release_candidate: expectedReleaseCandidate,
      actual_release_candidate: manifest.release_candidate,
    });
  }

  if (contractManifest) {
    const drift = findRequiredEvidenceDrift(manifest, contractManifest);
    if (drift.length > 0) {
      summary.strict_release_ready = false;
      summary.non_manifest_blockers += 1;
      summary.blocking_items.push(describeContractDriftBlocker(drift));
    }
  }

  let manifestStatusBlockers = 0;
  for (const item of manifest.items) {
    summary[item.status] += 1;
    const strictBlocking = item.status !== 'passed' && !isAllowedSignoffAcceptedRisk(item, { today });
    if (strictBlocking) {
      manifestStatusBlockers += 1;
      summary.strict_release_ready = false;
      summary.blocking_items.push(describeBlockingItem(item));
    }
  }

  if (strictPathReport && strictPathReport.threshold_pass !== true) {
    summary.strict_release_ready = false;
    summary.non_manifest_blockers += 1;
    summary.blocking_items.push(describeStrictPathBlocker(strictPathReport));
  }

  if (manifestStatusBlockers === 0 && summary.non_manifest_blockers === 0 && isReleaseEnvironment(manifest.environment)) {
    try {
      validateManifest(manifest, { strictRelease: true, today });
    } catch (error) {
      summary.strict_release_ready = false;
      summary.non_manifest_blockers += 1;
      summary.blocking_items.push(describeStrictReleaseValidationBlocker(error));
    }
  }

  return summary;
}

function isReleaseEnvironment(environment) {
  return ['staging', 'production', 'prod'].includes(environment);
}

function findRequiredEvidenceDrift(manifest, contractManifest) {
  const contractItems = new Map(contractManifest.items.map((item) => [item.id, item]));
  const drift = [];
  for (const item of manifest.items) {
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
      drift.push({
        id: item.id,
        expected_count: expected.length,
        actual_count: actual.length,
      });
    }
  }
  return drift;
}

function sameStringArray(left, right) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function describeContractDriftBlocker(drift) {
  return {
    id: 'STAGING-EVIDENCE-CONTRACT',
    category: 'staging-evidence',
    status: 'failed',
    description: 'Environment-specific pending evidence requirements are stale relative to production-readiness/staging-evidence.example.json.',
    required_evidence: drift.map((item) => `${item.id} required_evidence must be refreshed from the checked-in example contract (${item.actual_count} current entries, ${item.expected_count} expected entries)`),
    drift_items: drift.map((item) => item.id),
  };
}

function isAllowedSignoffAcceptedRisk(item, { today }) {
  return item.id === 'SEC-SIGNOFF-001'
    && item.status === 'accepted_risk'
    && item.decision_ref === allowedSignoffAcceptedRiskDecisionRef
    && item.review_due_at >= today
    && item.expires_at >= today
    && item.review_due_at <= item.expires_at;
}

function describeStrictPathBlocker(report) {
  const missing = [
    ...report.required,
    ...report.optional.filter((command) => command.required),
  ].filter((command) => !command.ok);
  return {
    id: 'STAGING-PATH-TOOLS',
    category: 'local-evidence-readiness',
    status: 'failed',
    description: 'Strict staging PATH readiness is missing tools required before production evidence collection.',
    required_evidence: missing.map((command) => {
      if (command.paths?.length > 0 && command.version_ok === false) {
        return `${command.name} on PATH with a successful version check (currently resolves but version check failed: ${command.version})`;
      }
      const remediation = command.remediation ? ` (${command.remediation})` : '';
      return `${command.name} on PATH${remediation}`;
    }),
    searched_paths: missing
      .filter((command) => Array.isArray(command.searched_paths) && command.searched_paths.length > 0)
      .map((command) => ({
        name: command.name,
        paths: command.searched_paths,
      })),
  };
}

function describeStrictReleaseValidationBlocker(error) {
  return {
    id: 'STAGING-EVIDENCE-STRICT-VALIDATION',
    category: 'staging-evidence',
    status: 'failed',
    description: 'Staging evidence manifest has no status-level blockers but fails strict release validation.',
    required_evidence: [error instanceof Error ? error.message : String(error)],
  };
}

function describeBlockingItem(item) {
  const result = {
    id: item.id,
    category: item.category,
    status: item.status,
    description: item.description,
  };
  if (item.status === 'pending_external') {
    result.required_evidence = item.required_evidence;
  }
  if (item.status === 'blocked' || item.status === 'failed') {
    result.owner = item.owner;
    result.blocker = item.blocker;
  }
  if (item.status === 'accepted_risk') {
    result.decision_ref = item.decision_ref;
    result.owner = item.owner;
    result.accepted_by = item.accepted_by;
    result.review_due_at = item.review_due_at;
    result.expires_at = item.expires_at;
  }
  return result;
}

export function formatText(summary) {
  const lines = [
    `staging evidence gaps for ${summary.environment} (${summary.release_candidate})`,
    summary.expected_release_candidate
      ? `expected release candidate: ${summary.expected_release_candidate} (${summary.release_candidate_matches_expected ? 'matches' : 'mismatch'})`
      : 'expected release candidate: not checked',
    `status counts: passed=${summary.passed}, pending_external=${summary.pending_external}, blocked=${summary.blocked}, failed=${summary.failed}, accepted_risk=${summary.accepted_risk}`,
    `non-manifest blockers: ${summary.non_manifest_blockers}`,
    `strict staging PATH ready: ${summary.strict_staging_path_ready === null ? 'not checked' : summary.strict_staging_path_ready ? 'yes' : 'no'}`,
    `strict release ready: ${summary.strict_release_ready ? 'yes' : 'no'}`,
    `proof markers: ${summary.proof_markers.join(', ')}`,
  ];

  if (summary.blocking_items.length > 0) {
    lines.push('blocking items:');
    for (const item of summary.blocking_items) {
      lines.push(`- ${item.id} [${item.status}] ${item.description}`);
      if (item.required_evidence?.length > 0) {
        for (const evidence of item.required_evidence) {
          lines.push(`  required: ${evidence}`);
        }
      }
      if (item.blocker) {
        lines.push(`  owner: ${item.owner}`);
        lines.push(`  blocker: ${item.blocker}`);
      }
      if (item.decision_ref) {
        lines.push(`  decision_ref: ${item.decision_ref}`);
        lines.push(`  owner: ${item.owner}`);
        lines.push(`  accepted_by: ${item.accepted_by}`);
        lines.push(`  review_due_at: ${item.review_due_at}`);
        lines.push(`  expires_at: ${item.expires_at}`);
      }
      if (item.expected_release_candidate) {
        lines.push(`  expected: ${item.expected_release_candidate}`);
        lines.push(`  actual: ${item.actual_release_candidate}`);
      }
      if (item.searched_paths?.length > 0) {
        for (const search of item.searched_paths) {
          lines.push(`  searched ${search.name}:`);
          for (const searchedPath of search.paths) {
            lines.push(`    ${searchedPath}`);
          }
        }
      }
    }
  }

  const blockingItemIDs = summary.blocking_items.map((item) => item.id).join('|') || 'none';
  lines.push(`gap report proof footer: strict_release_ready=${summary.strict_release_ready ? 'yes' : 'no'}, strict_staging_path_ready=${summary.strict_staging_path_ready === null ? 'not_checked' : summary.strict_staging_path_ready ? 'yes' : 'no'}, blocking_items=${summary.blocking_items.length}, blocking_item_ids=${blockingItemIDs}, counts=passed:${summary.passed}|pending_external:${summary.pending_external}|blocked:${summary.blocked}|failed:${summary.failed}|accepted_risk:${summary.accepted_risk}|non_manifest:${summary.non_manifest_blockers}, proof_markers=${summary.proof_markers.join(', ')}`);
  return `${lines.join('\n')}\n`;
}

export function formatObsidian(summary) {
  const lines = [
    `## Staging Evidence Snapshot (${summary.environment})`,
    `- release_candidate: ${summary.release_candidate}`,
    `- strict_release_ready: ${summary.strict_release_ready ? 'yes' : 'no'}`,
    `- strict_staging_path_ready: ${summary.strict_staging_path_ready === null ? 'not checked' : summary.strict_staging_path_ready ? 'yes' : 'no'}`,
    `- non_manifest_blockers: ${summary.non_manifest_blockers}`,
    `- counts: passed=${summary.passed}, pending_external=${summary.pending_external}, blocked=${summary.blocked}, failed=${summary.failed}, accepted_risk=${summary.accepted_risk}`,
    `- proof_markers: ${summary.proof_markers.join(', ')}`,
  ];
  if (summary.expected_release_candidate) {
    lines.push(`- expected_release_candidate: ${summary.expected_release_candidate}`);
    lines.push(`- release_candidate_matches_expected: ${summary.release_candidate_matches_expected ? 'yes' : 'no'}`);
  } else {
    lines.push('- expected_release_candidate: not checked');
  }
  if (summary.blocking_items.length === 0) {
    lines.push('- no blocking items');
    return `${lines.join('\n')}\n`;
  }
  lines.push('- blocking items:');
  for (const item of summary.blocking_items) {
    lines.push(`  - ${item.id} [${item.status}]: ${item.description}`);
    if (item.required_evidence?.length > 0) {
      for (const evidence of item.required_evidence) {
        lines.push(`    - required: ${evidence}`);
      }
    }
    if (item.blocker) {
      lines.push(`    - owner: ${item.owner}`);
      lines.push(`    - blocker: ${item.blocker}`);
    }
    if (item.decision_ref) {
      lines.push(`    - decision_ref: ${item.decision_ref}`);
      lines.push(`    - owner: ${item.owner}`);
      lines.push(`    - accepted_by: ${item.accepted_by}`);
      lines.push(`    - review_due_at: ${item.review_due_at}`);
      lines.push(`    - expires_at: ${item.expires_at}`);
    }
    if (item.expected_release_candidate) {
      lines.push(`    - expected_release_candidate: ${item.expected_release_candidate}`);
      lines.push(`    - actual_release_candidate: ${item.actual_release_candidate}`);
    }
    if (item.searched_paths?.length > 0) {
      for (const search of item.searched_paths) {
        lines.push(`    - searched ${search.name}:`);
        for (const searchedPath of search.paths) {
          lines.push(`      - ${searchedPath}`);
        }
      }
    }
  }
  return `${lines.join('\n')}\n`;
}

async function readJSON(path) {
  const content = await readFile(path, 'utf8');
  return JSON.parse(content.replace(/^\uFEFF/, ''));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifest = await readJSON(args.manifest);
  const contractManifest = args.contractManifest ? await readJSON(args.contractManifest) : null;
  const expectedReleaseCandidate = args.expectedReleaseCandidate ?? readCurrentGitHead(process.cwd());
  const summary = summarizeGaps(manifest, {
    expectedReleaseCandidate,
    strictPathReport: buildPathReport({ strictStaging: true }),
    contractManifest,
  });
  if (args.format === 'json') {
    console.log(JSON.stringify(summary, null, 2));
  } else if (args.format === 'obsidian') {
    process.stdout.write(formatObsidian(summary));
  } else {
    process.stdout.write(formatText(summary));
  }
  if (!summary.strict_release_ready && !args.allowBlockers) {
    process.exitCode = 1;
  }
}

function readCurrentGitHead(cwd) {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('report-staging-evidence-gaps.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
