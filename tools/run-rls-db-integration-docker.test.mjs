import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildDatabaseURL,
  buildDockerExecCommand,
  buildDockerRunCommand,
  defaultDockerRLSConfig,
  migrationFiles,
  parseDockerRLSArgs,
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
});

test('runDockerRLSDBIntegration rejects when docker is unavailable', async () => {
  let callCount = 0;
  const commands = [];
  const runner = async (command) => {
    callCount += 1;
    commands.push(command);
    if (command[0] === 'docker' && command[1] === '--version') {
      return { exitCode: 1, stdout: '', stderr: 'docker not available' };
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
    /Docker is unavailable in this environment\./,
  );
  assert.equal(callCount >= 1, true);
  assert.equal(commands.some((command) => command[0] === 'docker' && command[1] === '--version'), true);
  assert.equal(commands.some((command) => command[0] === 'docker' && command[1] === 'container' && command[2] === 'inspect'), false);
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
