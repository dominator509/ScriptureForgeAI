import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { runRLSDBIntegration } from './run-rls-db-integration.mjs';

export const defaultDockerRLSConfig = {
  image: 'pgvector/pgvector:pg16',
  containerName: 'scriptureforge-rls-db',
  host: 'localhost',
  port: '55433',
  database: 'scriptureforge',
  user: 'postgres',
  password: 'scriptureforge',
  keep: false,
  dockerCommandTimeoutMs: 10000,
  dockerRunTimeoutMs: 120000,
  healthRetries: 30,
  healthDelayMs: 1000,
};

export const migrationFiles = [
  '/migrations/000001_init_extensions.up.sql',
  '/migrations/000002_core_schema.up.sql',
  '/migrations/000003_scripture_text_reference.up.sql',
  '/migrations/000004_auth_mfa_assurance.up.sql',
  '/migrations/000005_mfa_legacy_plaintext_cleanup.up.sql',
];

export function parseDockerRLSArgs(argv = []) {
  const config = { ...defaultDockerRLSConfig };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--keep') {
      config.keep = true;
    } else if (arg === '--image') {
      config.image = requireValue(argv, i += 1, arg);
    } else if (arg === '--container-name') {
      config.containerName = requireValue(argv, i += 1, arg);
    } else if (arg === '--port') {
      config.port = requireValue(argv, i += 1, arg);
    } else {
      throw new Error(`unknown argument ${arg}`);
    }
  }
  return config;
}

export function buildDatabaseURL(config = defaultDockerRLSConfig) {
  return `postgres://${config.user}:${config.password}@${config.host}:${config.port}/${config.database}?sslmode=disable`;
}

export function buildDockerRunCommand(config = defaultDockerRLSConfig, workspaceRoot = process.cwd()) {
  return [
    'docker',
    'run',
    '--name',
    config.containerName,
    '-e',
    `POSTGRES_PASSWORD=${config.password}`,
    '-e',
    `POSTGRES_DB=${config.database}`,
    '-p',
    `${config.port}:5432`,
    '-v',
    `${resolve(workspaceRoot, 'migrations')}:/migrations:ro`,
    '-d',
    config.image,
  ];
}

export function buildDockerExecCommand(config = defaultDockerRLSConfig, command = []) {
  return [
    'docker',
    'exec',
    '-e',
    `PGPASSWORD=${config.password}`,
    config.containerName,
    ...command,
  ];
}

export async function runDockerRLSDBIntegration({
  config = defaultDockerRLSConfig,
  workspaceRoot = process.cwd(),
  runner = runCommand,
  rlsRunner = runRLSDBIntegration,
  env = process.env,
} = {}) {
  const runDockerCommand = (command, options = {}) => runner(command, {
    ...options,
    timeoutMs: options.timeoutMs ?? (command[1] === 'run'
      ? config.dockerRunTimeoutMs
      : config.dockerCommandTimeoutMs),
  });
  const dockerAvailable = await ensureDockerAvailable(runDockerCommand);
  if (!dockerAvailable) {
    throw new Error(
      'Docker daemon is unavailable in this environment. Start the Docker daemon or run node tools/run-rls-db-integration.mjs with DATABASE_URL set to a migrated database.'
    );
  }
  await ensureContainerNameAvailable(config, runDockerCommand);
  await runDockerCommand(buildDockerRunCommand(config, workspaceRoot));
  try {
    await waitForPostgres(config, runDockerCommand);
    for (const migrationFile of migrationFiles) {
      await runDockerCommand(buildDockerExecCommand(config, [
        'psql',
        '-U',
        config.user,
        '-d',
        config.database,
        '-v',
        'ON_ERROR_STOP=1',
        '-f',
        migrationFile,
      ]));
    }
    return await rlsRunner({
      workspaceRoot,
      env: {
        ...env,
        DATABASE_URL: buildDatabaseURL(config),
        JWT_SECRET_KEY: env.JWT_SECRET_KEY || 'local-rls-integration-secret-for-scriptureforge',
      },
    });
  } finally {
    if (!config.keep) {
      await runDockerCommand(['docker', 'rm', '-f', config.containerName], { allowFailure: true });
    }
  }
}

async function ensureDockerAvailable(runner) {
  try {
    const result = await runner(['docker', 'info', '--format', '{{.ServerVersion}}'], { allowFailure: true, quiet: true });
    return result.exitCode === 0;
  } catch {
    return false;
  }
}

async function ensureContainerNameAvailable(config, runner) {
  const result = await runner(['docker', 'container', 'inspect', config.containerName], { allowFailure: true, quiet: true });
  if (result.exitCode === 0) {
    throw new Error(`Docker container ${config.containerName} already exists; remove it or pass --container-name with a disposable name`);
  }
}

async function waitForPostgres(config, runner) {
  let lastError = '';
  for (let attempt = 0; attempt < config.healthRetries; attempt += 1) {
    const result = await runner(buildDockerExecCommand(config, [
      'psql',
      '-U',
      config.user,
      '-d',
      config.database,
      '-v',
      'ON_ERROR_STOP=1',
      '-c',
      'SELECT 1',
    ]), { allowFailure: true, quiet: true });
    if (result.exitCode === 0) {
      return;
    }
    lastError = result.stderr || result.stdout;
    await delay(config.healthDelayMs);
  }
  throw new Error(`Postgres container did not become ready: ${lastError.trim()}`);
}

export function runCommand(command, {
  allowFailure = false,
  quiet = false,
  timeoutMs = 30000,
} = {}) {
  return new Promise((resolveRun, reject) => {
    const [program, ...args] = command;
    const child = spawn(program, args, {
      shell: false,
      stdio: quiet ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    let timer;
    const settleFailure = (error) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      reject(error);
    };
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', settleFailure);
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      const exitCode = code ?? 1;
      const result = { exitCode, stdout, stderr };
      if (exitCode !== 0 && !allowFailure) {
        reject(new Error(`${program} exited with ${exitCode}${stderr.trim() ? `: ${stderr.trim()}` : ''}`));
        return;
      }
      resolveRun(result);
    });
    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      timer = setTimeout(() => {
        if (settled) return;
        const message = `${program} timed out after ${timeoutMs}ms`;
        stderr = `${stderr}${stderr ? '\n' : ''}${message}`;
        child.kill();
        settled = true;
        clearTimeout(timer);
        const result = { exitCode: 124, stdout, stderr };
        if (allowFailure) {
          resolveRun(result);
        } else {
          const error = new Error(message);
          error.code = 'ETIMEDOUT';
          reject(error);
        }
      }, timeoutMs);
    }
  });
}

function requireValue(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith('--')) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function delay(ms) {
  return new Promise((resolveDelay) => {
    setTimeout(resolveDelay, ms);
  });
}

async function main() {
  try {
    const config = parseDockerRLSArgs(process.argv.slice(2));
    const exitCode = await runDockerRLSDBIntegration({ config });
    process.exit(exitCode);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-rls-db-integration-docker.mjs')) {
  main();
}
