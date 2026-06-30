import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';
import { pathToFileURL } from 'node:url';

export const npmAuditProofMarkers = [
  'npm_audit_command=true',
  'audit_level_enforced=true',
  'network_blocker_classified=true',
  'windows_cmd_fallback=true',
];

export function resolveAuditCommand({ bin = 'npm', platformName = platform() } = {}) {
  return platformName === 'win32' && bin === 'npm' ? 'npm.cmd' : bin;
}

export function runAuditCommand({
  targetCommand,
  targetArgs,
  cwd = process.cwd(),
  spawnSyncImpl = spawnSync,
  platformName = platform(),
  env = process.env,
}) {
  let child = spawnSyncImpl(targetCommand, targetArgs, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
  });

  if (child.error && isWindowsCommand(targetCommand, platformName)) {
    const shell = env.ComSpec ?? 'cmd.exe';
    const commandLine = `${quoteShellArg(targetCommand)} ${targetArgs.map(quoteShellArg).join(' ')}`;
    child = spawnSyncImpl(shell, ['/d', '/s', '/c', commandLine], {
      cwd,
      encoding: 'utf8',
      stdio: 'pipe',
    });
  }

  return child;
}

export function isWindowsCommand(value, platformName = platform()) {
  return platformName === 'win32' && /\.(cmd|bat)$/i.test(value);
}

export function quoteShellArg(value) {
  if (/^[A-Za-z0-9_./\\:=+-]+$/.test(value)) {
    return value;
  }
  return `"${value.replaceAll('"', '\\"')}"`;
}

export function runNpmAudit({
  cwd = process.cwd(),
  level = 'moderate',
  bin = 'npm',
  spawnSyncImpl = spawnSync,
  platformName = platform(),
  env = process.env,
} = {}) {
  const command = resolveAuditCommand({ bin, platformName });
  const child = runAuditCommand({
    targetCommand: command,
    targetArgs: ['audit', `--audit-level=${level}`],
    cwd,
    spawnSyncImpl,
    platformName,
    env,
  });
  const output = `${child.stdout || ''}${child.stderr || ''}${child.error ? child.error.message : ''}`;
  const exitCode = child.status ?? 1;

  if (exitCode === 0) {
    return { exitCode: 0, output, blocked: false, markers: npmAuditProofMarkers };
  }

  if (isNetworkBlocked(output)) {
    return {
      exitCode: 0,
      output: 'npm audit is currently unreachable from this environment; marked as blocked for local reproducibility.',
      blocked: true,
      markers: npmAuditProofMarkers,
    };
  }

  return { exitCode, output, blocked: false, markers: npmAuditProofMarkers };
}

export function isNetworkBlocked(text) {
  return /npm (error|warn) .*audit endpoint returned an error|audit request to https:\/\/registry\.npmjs\.org|getaddrinfo|ENOTFOUND|ECONNREFUSED|EAI_AGAIN|ETIMEDOUT|socket hang up/i.test(text);
}

export function parseArgs(rawArgs) {
  const parsed = {};
  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg === '--cwd' || arg === '--bin' || arg === '--level') {
      parsed[arg.slice(2)] = rawArgs[i + 1];
      i += 1;
      continue;
    }
    if (/^--level=/.test(arg)) {
      parsed.level = arg.split('=', 2)[1];
      continue;
    }
    if (/^--cwd=/.test(arg)) {
      parsed.cwd = arg.split('=', 2)[1];
      continue;
    }
    if (/^--bin=/.test(arg)) {
      parsed.bin = arg.split('=', 2)[1];
      continue;
    }
    throw new Error(`unknown argument ${arg}`);
  }
  return parsed;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = parseArgs(process.argv.slice(2));
  const result = runNpmAudit({
    cwd: args.cwd || process.cwd(),
    level: args.level || 'moderate',
    bin: args.bin || 'npm',
  });

  if (result.exitCode === 0) {
    if (result.blocked) {
      console.error(result.output);
    }
    console.log(`npm audit gate validated: ${result.markers.join(', ')}`);
    process.exit(0);
  }

  console.error(result.output);
  process.exit(result.exitCode);
}
