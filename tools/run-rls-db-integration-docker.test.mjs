import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  buildDatabaseURL,
  buildDockerExecCommand,
  buildDockerRunCommand,
  defaultDockerRLSConfig,
  migrationFiles,
  parseDockerRLSArgs,
  runCommand,
  runDockerRLSDBIntegration,
} from './run-rls-db-integration-docker.mjs';

test('parseDockerRLSArgs keeps conservative defaults and supports overrides', () => {
  assert.deepEqual(parseDockerRLSArgs([]), defaultDockerRLSConfig);
  assert.deepEqual(parseDockerRLSArgs([
    '--keep',
    '--port',
    '55434',
    '--container-name',
    'sfai-test-db',
    '--image',
    'pgvector/pgvector:pg16',
  ]), {
    ...defaultDockerRLSConfig,
    keep: true,
    port: '55434',
    containerName: 'sfai-test-db',
  });
});

test('buildDockerRunCommand mounts migrations into pgvector container', () => {
  const command = buildDockerRunCommand(defaultDockerRLSConfig, 'C:\\dev\\ScriptureForgeAI');
  assert.deepEqual(command.slice(0, 4), ['docker', 'run', '--name', 'scriptureforge-rls-db']);
  assert.equal(command.includes('pgvector/pgvector:pg16'), true);
  assert.equal(command.includes('POSTGRES_PASSWORD=scriptureforge'), true);
  assert.equal(command.includes('POSTGRES_DB=scriptureforge'), true);
  assert.equal(command.includes('55433:5432'), true);
  assert.equal(command.some((part) => /migrations.*:\/migrations:ro/.test(part)), true);
});

test('buildDockerExecCommand executes psql inside the container', () => {
  const command = buildDockerExecCommand(defaultDockerRLSConfig, [
    'psql',
    '-U',
    'postgres',
    '-d',
    'scriptureforge',
  ]);
  assert.deepEqual(command.slice(0, 6), ['docker', 'exec', '-e', 'PGPASSWORD=scriptureforge', 'scriptureforge-rls-db', 'psql']);
});

test('buildDatabaseURL matches the local Docker database', () => {
  assert.equal(
    buildDatabaseURL(defaultDockerRLSConfig),
    'postgres://postgres:scriptureforge@localhost:55433/scriptureforge?sslmode=disable',
  );
});

test('migration list applies the complete ordered up-migration set', () => {
  assert.deepEqual(migrationFiles, [
    '/migrations/000001_init_extensions.up.sql',
    '/migrations/000002_core_schema.up.sql',
    '/migrations/000003_scripture_text_reference.up.sql',
    '/migrations/000004_auth_mfa_assurance.up.sql',
    '/migrations/000005_mfa_legacy_plaintext_cleanup.up.sql',
  ]);
});

test('legacy MFA cleanup clears unversioned seeds and fails closed on rollback', async () => {
  const up = await readFile(resolve('migrations/000005_mfa_legacy_plaintext_cleanup.up.sql'), 'utf8');
  const down = await readFile(resolve('migrations/000005_mfa_legacy_plaintext_cleanup.down.sql'), 'utf8');
  assert.match(up, /mfa_secret\s*=\s*NULL/);
  assert.match(up, /mfa_enabled\s*=\s*FALSE/);
  assert.match(up, /mfa_secret\s+NOT LIKE\s+'v1\.%'/);
  assert.match(down, /intentionally irreversible/i);
  assert.match(down, /RAISE EXCEPTION/i);
});

test('runDockerRLSDBIntegration applies migrations, runs RLS tests, and cleans up', async () => {
  const calls = [];
  const config = {
    ...defaultDockerRLSConfig,
    healthDelayMs: 0,
    healthRetries: 1,
  };
  const runner = async (command, options = {}) => {
    calls.push({ command, options });
    if (command.includes('inspect')) return { exitCode: 1, stdout: '', stderr: '' };
    return { exitCode: 0, stdout: '', stderr: '' };
  };
  let observedEnv;
  const exitCode = await runDockerRLSDBIntegration({
    config,
    workspaceRoot: 'C:\\dev\\ScriptureForgeAI',
    runner,
    rlsRunner: async ({ env }) => {
      observedEnv = env;
      return 0;
    },
    env: {},
  });

  assert.equal(exitCode, 0);
  assert.equal(calls.some(({ command }) => command.slice(0, 2).join(' ') === 'docker run'), true);
  assert.equal(calls.some(({ command }) => command.includes('SELECT 1')), true);
  for (const migrationFile of migrationFiles) {
    assert.equal(calls.some(({ command }) => command.includes(migrationFile)), true);
  }
  assert.equal(calls.at(-1).command.join(' '), 'docker rm -f scriptureforge-rls-db');
  assert.equal(observedEnv.DATABASE_URL, buildDatabaseURL(config));
  assert.equal(observedEnv.JWT_SECRET_KEY, 'local-rls-integration-secret-for-scriptureforge');
  assert.equal(calls.find(({ command }) => command[1] === 'info').options.timeoutMs, config.dockerCommandTimeoutMs);
  assert.equal(calls.find(({ command }) => command[1] === 'run').options.timeoutMs, config.dockerRunTimeoutMs);
});

test('runDockerRLSDBIntegration rejects when docker is unavailable', async () => {
  let callCount = 0;
  const commands = [];
  const runner = async (command) => {
    callCount += 1;
    commands.push(command);
    if (command[0] === 'docker' && command[1] === 'info') {
      return { exitCode: 1, stdout: '', stderr: 'docker daemon not available' };
    }
    if (command.includes('inspect')) return { exitCode: 0, stdout: '{}', stderr: '' };
    return { exitCode: 0, stdout: '', stderr: '' };
  };

  await assert.rejects(
    () => runDockerRLSDBIntegration({
      config: defaultDockerRLSConfig,
      runner,
      rlsRunner: async () => 0,
    env: {},
  }),
    /Docker daemon is unavailable in this environment\./,
  );
  assert.equal(callCount >= 1, true);
  assert.equal(commands.some((command) => command[0] === 'docker' && command[1] === 'info'), true);
  assert.equal(commands.some((command) => command[0] === 'docker' && command[1] === 'container' && command[2] === 'inspect'), false);
});

test('runCommand fails fast when a Docker subprocess does not return', async () => {
  const startedAt = Date.now();
  const result = await runCommand([
    process.execPath,
    '-e',
    'setTimeout(() => {}, 5000)',
  ], {
    allowFailure: true,
    quiet: true,
    timeoutMs: 25,
  });

  assert.equal(result.exitCode, 124);
  assert.match(result.stderr, /timed out after 25ms/);
  assert.ok(Date.now() - startedAt < 1000);
});

test('runDockerRLSDBIntegration refuses to reuse an existing container name', async () => {
  await assert.rejects(
    () => runDockerRLSDBIntegration({
      config: { ...defaultDockerRLSConfig, healthDelayMs: 0 },
      runner: async (command) => {
        if (command.includes('inspect')) return { exitCode: 0, stdout: '{}', stderr: '' };
        return { exitCode: 0, stdout: '', stderr: '' };
      },
      rlsRunner: async () => 0,
      env: {},
    }),
    /already exists/,
  );
});
