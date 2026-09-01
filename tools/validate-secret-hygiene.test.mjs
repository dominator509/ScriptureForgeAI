import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  secretHygieneProofMarkers,
  validateSecretHygiene,
  validateSecretHygieneSources,
} from './validate-secret-hygiene.mjs';

const safeGitignore = [
  '.env',
  '.env.*',
  '!.env.example',
  '*.tfstate',
  '*.tfstate.*',
  '.terraform/',
].join('\n');

const safeTfvarsExample = [
  'api_image_digest = "replace-with-digest"',
  'jwt_secret = "replace-with-at-least-16-characters"',
  'aws_account_id = "123456789012"',
  'secret_arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:example"',
  'certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/example"',
].join('\n');

function fixture(overrides = {}) {
  return {
    trackedFiles: ['README.md', 'build/terraform/main.tf'],
    untrackedFiles: ['tools/local-note.mjs'],
    fileContents: {
      'README.md': 'ScriptureForgeAI local fixture without secrets.',
      'build/terraform/main.tf': 'variable "api_image_digest" {}',
      'tools/local-note.mjs': 'export const ok = true;',
    },
    gitignore: safeGitignore,
    tfvarsExample: safeTfvarsExample,
    ...overrides,
  };
}

describe('validate-secret-hygiene', () => {
  it('accepts the current repository secret hygiene state', () => {
    const result = validateSecretHygiene();

    assert.equal(result.fileCount > 0, true);
    assert.deepEqual(result.markers, secretHygieneProofMarkers);
  });

  it('accepts safe tracked and untracked text fixtures', () => {
    const result = validateSecretHygieneSources(fixture());

    assert.equal(result.fileCount, 3);
    assert.deepEqual(result.markers, secretHygieneProofMarkers);
  });

  it('rejects local env files even when they are untracked', () => {
    assert.throws(
      () => validateSecretHygieneSources(fixture({
        untrackedFiles: ['.env.local'],
        fileContents: { '.env.local': 'DATABASE_URL=postgres://user:pass@example/db' },
      })),
      /local env files must not be tracked or unignored/,
    );
  });

  it('rejects high-confidence token and key patterns', () => {
    for (const [name, content] of [
      ['OpenAI API key', `OPENAI_API_KEY=${'sk-proj-'}${'abcdefghijklmnopqrstuvwxyz123456'}`],
      ['AWS access key', `AWS_ACCESS_KEY_ID=${'AKIA'}${'1234567890ABCDEF'}`],
      ['GitHub token', `GITHUB_TOKEN=${'ghp_'}${'abcdefghijklmnopqrstuvwxyzABCDE'}`],
      ['Slack token', `SLACK_BOT_TOKEN=${'xoxb-'}${'123456789012-abcdefghijklmnopqr'}`],
      ['private key block', `${'-----BEGIN '}PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----`],
    ]) {
      assert.throws(
        () => validateSecretHygieneSources(fixture({
          trackedFiles: [`security/${name}.md`],
          fileContents: { [`security/${name}.md`]: content },
        })),
        new RegExp(`high-confidence ${name}`),
      );
    }
  });

  it('rejects missing gitignore protections for env files and Terraform state', () => {
    assert.throws(
      () => validateSecretHygieneSources(fixture({ gitignore: '.env\n!.env.example\n.terraform/' })),
      /\.gitignore missing \.env\.\*/,
    );

    assert.throws(
      () => validateSecretHygieneSources(fixture({ gitignore: '.env\n.env.*\n!.env.example\n.terraform/' })),
      /\.gitignore missing \*\.tfstate/,
    );
  });

  it('rejects Terraform examples without placeholder markers', () => {
    assert.throws(
      () => validateSecretHygieneSources(fixture({
        tfvarsExample: safeTfvarsExample.replace('replace-with-digest', 'sha256:abc123'),
      })),
      /terraform\.tfvars\.example missing placeholder marker replace-with-digest/,
    );
  });
});
