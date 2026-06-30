import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename, extname } from 'node:path';
import { pathToFileURL } from 'node:url';

export const secretHygieneProofMarkers = [
  'tracked_files_scanned=true',
  'untracked_files_scanned=true',
  'env_files_rejected=true',
  'high_confidence_secret_patterns_scanned=true',
  'gitignore_env_patterns=true',
  'gitignore_tfstate_patterns=true',
  'terraform_placeholder_markers=true',
  'plaintext_secret_findings_zero=true',
];

export const textExtensions = new Set([
  '',
  '.go',
  '.js',
  '.json',
  '.md',
  '.mjs',
  '.mts',
  '.rs',
  '.sql',
  '.tf',
  '.toml',
  '.tsx',
  '.ts',
  '.txt',
  '.yaml',
  '.yml',
]);

export const highConfidencePatterns = [
  { name: 'OpenAI API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b/g },
  { name: 'AWS access key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/g },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
  { name: 'private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----/g },
];

export function listGitFiles(args) {
  return execFileSync('git', args, { encoding: 'utf8' })
    .split(/\r?\n/)
    .filter(Boolean);
}

export function selectSecretHygieneFiles(trackedFiles, untrackedFiles, extensions = textExtensions) {
  return [...trackedFiles, ...untrackedFiles]
    .filter((file) => extensions.has(extname(file)) || basename(file).startsWith('.env'));
}

export function scanSecretHygieneFiles(files, fileContents, patterns = highConfidencePatterns) {
  const findings = [];

  for (const file of files) {
    if (file.includes('package-lock.json') || file.includes('Cargo.lock')) continue;
    if (/^\.env(?:\.|$)/.test(basename(file)) && !file.endsWith('.example')) {
      findings.push(`${file}: local env files must not be tracked or unignored`);
      continue;
    }

    const content = fileContents[file];
    if (typeof content !== 'string') continue;
    for (const { name, pattern } of patterns) {
      pattern.lastIndex = 0;
      for (const match of content.matchAll(pattern)) {
        findings.push(`${file}: high-confidence ${name} candidate near index ${match.index}`);
      }
    }
  }

  return findings;
}

export function validateSecretHygieneSources({
  trackedFiles = [],
  untrackedFiles = [],
  fileContents = {},
  gitignore,
  tfvarsExample,
} = {}) {
  const files = selectSecretHygieneFiles(trackedFiles, untrackedFiles);

  for (const required of ['.env', '.env.*', '!.env.example', '*.tfstate', '*.tfstate.*', '.terraform/']) {
    assert.ok(gitignore.includes(required), `.gitignore missing ${required}`);
  }

  for (const placeholder of [
    'replace-with-digest',
    'replace-with-at-least-16-characters',
    '123456789012',
    'arn:aws:secretsmanager:',
    'arn:aws:acm:',
  ]) {
    assert.ok(tfvarsExample.includes(placeholder), `terraform.tfvars.example missing placeholder marker ${placeholder}`);
  }

  const findings = scanSecretHygieneFiles(files, fileContents);
  if (findings.length > 0) {
    throw new Error(`Secret hygiene validation failed:\n${findings.join('\n')}`);
  }

  return { markers: secretHygieneProofMarkers, fileCount: files.length };
}

export function loadSecretHygieneSources({
  trackedFiles = listGitFiles(['ls-files']),
  untrackedFiles = listGitFiles(['ls-files', '--others', '--exclude-standard']),
} = {}) {
  const files = selectSecretHygieneFiles(trackedFiles, untrackedFiles);
  const fileContents = {};

  for (const file of files) {
    try {
      fileContents[file] = readFileSync(file, 'utf8');
    } catch {
      // Git may list a file that disappeared during validation; scanning the rest is still useful.
    }
  }

  return {
    trackedFiles,
    untrackedFiles,
    fileContents,
    gitignore: readFileSync('.gitignore', 'utf8'),
    tfvarsExample: readFileSync('build/terraform/terraform.tfvars.example', 'utf8'),
  };
}

export function validateSecretHygiene() {
  return validateSecretHygieneSources(loadSecretHygieneSources());
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = validateSecretHygiene();
  console.log(`secret hygiene validated across ${result.fileCount} text files: ${result.markers.join(', ')}`);
}
