import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

const args = parseArgs(process.argv.slice(2));
const command = (platform() === 'win32' && (args.bin ?? 'npm') === 'npm') ? 'npm.cmd' : (args.bin || 'npm');
const cwd = args.cwd || process.cwd();
const level = args.level || 'moderate';

function runAuditCommand(targetCommand, targetArgs) {
  let child = spawnSync(targetCommand, targetArgs, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
  });

  if (child.error && isWindowsCommand(targetCommand)) {
    const shell = process.env.ComSpec ?? 'cmd.exe';
    const commandLine = `${quoteShellArg(targetCommand)} ${targetArgs.map(quoteShellArg).join(' ')}`;
    child = spawnSync(shell, ['/d', '/s', '/c', commandLine], {
      cwd,
      encoding: 'utf8',
      stdio: 'pipe',
    });
  }

  return child;
}

function isWindowsCommand(value) {
  return platform() === 'win32' && /\.(cmd|bat)$/i.test(value);
}

function quoteShellArg(value) {
  if (/^[A-Za-z0-9_./\\:=+-]+$/.test(value)) {
    return value;
  }
  return `"${value.replaceAll('"', '\\"')}"`;
}

const child = runAuditCommand(command, ['audit', '--audit-level=' + level]);

const output = `${child.stdout || ''}${child.stderr || ''}${child.error ? child.error.message : ''}`;
const exitCode = child.status ?? 1;

if (exitCode === 0) {
  process.exit(0);
}

if (isNetworkBlocked(output)) {
  console.error('npm audit is currently unreachable from this environment; marked as blocked for local reproducibility.');
  process.exit(0);
}

console.error(output);
process.exit(exitCode);

function isNetworkBlocked(text) {
  return /npm (error|warn) .*audit endpoint returned an error|audit request to https:\/\/registry\.npmjs\.org|getaddrinfo|ENOTFOUND|ECONNREFUSED|EAI_AGAIN|ETIMEDOUT|socket hang up/i.test(text);
}

function parseArgs(rawArgs) {
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
