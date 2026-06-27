import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { validateManifest } from './validate-staging-evidence.mjs';

function usage() {
  return [
    'Usage:',
    '  node tools/report-staging-evidence-gaps.mjs [--manifest <path>] [--format text|json|obsidian] [--expected-release-candidate <sha>]',
    '',
    'Validates a staging evidence manifest and reports the items that still block strict release readiness.',
  ].join('\n');
}

export function parseArgs(argv) {
  const args = {
    manifest: process.env.STAGING_EVIDENCE_FILE ?? 'production-readiness/staging-evidence.staging.json',
    format: 'text',
    expectedReleaseCandidate: process.env.EXPECTED_RELEASE_CANDIDATE,
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--manifest') {
      args.manifest = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--format') {
      args.format = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--expected-release-candidate') {
      args.expectedReleaseCandidate = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument ${argv[i]}\n${usage()}`);
    }
  }
  assert.ok(args.manifest, '--manifest must not be empty');
  assert.ok(
    ['text', 'json', 'obsidian'].includes(args.format),
    '--format must be text, json, or obsidian',
  );
  return args;
}

export function summarizeGaps(manifest, { expectedReleaseCandidate } = {}) {
  validateManifest(manifest);
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
    blocking_items: [],
  };

  if (expectedReleaseCandidate && manifest.release_candidate !== expectedReleaseCandidate) {
    summary.strict_release_ready = false;
    summary.blocking_items.push({
      id: 'RELEASE-CANDIDATE-SHA',
      category: 'source-control-ci',
      status: 'failed',
      description: 'Staging evidence manifest release_candidate does not match the expected release SHA.',
      expected_release_candidate: expectedReleaseCandidate,
      actual_release_candidate: manifest.release_candidate,
    });
  }

  for (const item of manifest.items) {
    summary[item.status] += 1;
    const strictBlocking = item.status !== 'passed' && !(item.id === 'SEC-SIGNOFF-001' && item.status === 'accepted_risk');
    if (strictBlocking) {
      summary.strict_release_ready = false;
      summary.blocking_items.push(describeBlockingItem(item));
    }
  }

  return summary;
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
    `strict release ready: ${summary.strict_release_ready ? 'yes' : 'no'}`,
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
      }
      if (item.expected_release_candidate) {
        lines.push(`  expected: ${item.expected_release_candidate}`);
        lines.push(`  actual: ${item.actual_release_candidate}`);
      }
    }
  }

  return `${lines.join('\n')}\n`;
}

export function formatObsidian(summary) {
  const lines = [
    `## Staging Evidence Snapshot (${summary.environment})`,
    `- release_candidate: ${summary.release_candidate}`,
    `- strict_release_ready: ${summary.strict_release_ready ? 'yes' : 'no'}`,
    `- counts: passed=${summary.passed}, pending_external=${summary.pending_external}, blocked=${summary.blocked}, failed=${summary.failed}, accepted_risk=${summary.accepted_risk}`,
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
    }
    if (item.expected_release_candidate) {
      lines.push(`    - expected_release_candidate: ${item.expected_release_candidate}`);
      lines.push(`    - actual_release_candidate: ${item.actual_release_candidate}`);
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
  const expectedReleaseCandidate = args.expectedReleaseCandidate ?? readCurrentGitHead(process.cwd());
  const summary = summarizeGaps(manifest, { expectedReleaseCandidate });
  if (args.format === 'json') {
    console.log(JSON.stringify(summary, null, 2));
  } else if (args.format === 'obsidian') {
    process.stdout.write(formatObsidian(summary));
  } else {
    process.stdout.write(formatText(summary));
  }
  if (!summary.strict_release_ready) {
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
