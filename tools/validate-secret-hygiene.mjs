import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { basename, extname } from 'node:path';

const textExtensions = new Set([
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

const highConfidencePatterns = [
  { name: 'OpenAI API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b/g },
  { name: 'AWS access key', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'GitHub token', pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/g },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g },
  { name: 'private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----/g },
];

const trackedFiles = execFileSync('git', ['ls-files'], { encoding: 'utf8' })
  .split(/\r?\n/)
  .filter(Boolean);
const untrackedFiles = execFileSync('git', ['ls-files', '--others', '--exclude-standard'], { encoding: 'utf8' })
  .split(/\r?\n/)
  .filter(Boolean);
const files = [...trackedFiles, ...untrackedFiles].filter((file) => textExtensions.has(extname(file)) || basename(file).startsWith('.env'));

const findings = [];

for (const file of files) {
  if (file.includes('package-lock.json') || file.includes('Cargo.lock')) continue;
  if (/^\.env(?:\.|$)/.test(basename(file)) && !file.endsWith('.example')) {
    findings.push(`${file}: local env files must not be tracked or unignored`);
    continue;
  }

  let content = '';
  try {
    content = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  for (const { name, pattern } of highConfidencePatterns) {
    pattern.lastIndex = 0;
    for (const match of content.matchAll(pattern)) {
      findings.push(`${file}: high-confidence ${name} candidate near index ${match.index}`);
    }
  }
}

const gitignore = readFileSync('.gitignore', 'utf8');
for (const required of ['.env', '.env.*', '!.env.example', '*.tfstate', '*.tfstate.*', '.terraform/']) {
  assert.ok(gitignore.includes(required), `.gitignore missing ${required}`);
}

const tfvarsExample = readFileSync('build/terraform/terraform.tfvars.example', 'utf8');
for (const placeholder of [
  'replace-with-digest',
  'replace-with-at-least-16-characters',
  '123456789012',
  'arn:aws:secretsmanager:',
  'arn:aws:acm:',
]) {
  assert.ok(tfvarsExample.includes(placeholder), `terraform.tfvars.example missing placeholder marker ${placeholder}`);
}

if (findings.length > 0) {
  throw new Error(`Secret hygiene validation failed:\n${findings.join('\n')}`);
}

console.log(`secret hygiene validated across ${files.length} text files`);
