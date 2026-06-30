import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

export const clientCommandProofMarkers = [
  'client_script_command=true',
  'script_success_required=true',
  'windows_cmd_fallback=true',
];

export function resolveClientCommand({ bin = 'npm', platformName = platform() } = {}) {
  return platformName === 'win32' && bin === 'npm' ? 'npm.cmd' : bin;
}

export function runClientCommand({
  cwd = process.cwd(),
  script,
  bin = 'npm',
  markers = [],
  spawnSyncImpl = spawnSync,
  platformName = platform(),
  env = process.env,
} = {}) {
  if (!script) {
    throw new Error('missing required --script');
  }
  const command = resolveClientCommand({ bin, platformName });
  let child = spawnSyncImpl(command, ['run', script], {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
  });

  if (child.error && isWindowsCommand(command, platformName)) {
    const shell = env.ComSpec ?? 'cmd.exe';
    const commandLine = [command, 'run', script].map(quoteShellArg).join(' ');
    child = spawnSyncImpl(shell, ['/d', '/s', '/c', commandLine], {
      cwd,
      encoding: 'utf8',
      stdio: 'pipe',
    });
  }

  const output = `${child.stdout || ''}${child.stderr || ''}${child.error ? child.error.message : ''}`;
  const exitCode = child.status ?? 1;
  return {
    exitCode,
    output,
    markers: [...clientCommandProofMarkers, ...markers],
  };
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

export function parseArgs(rawArgs) {
  const parsed = { markers: [] };
  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg === '--cwd' || arg === '--script' || arg === '--proof-name' || arg === '--bin') {
      parsed[arg.slice(2)] = rawArgs[i + 1];
      i += 1;
      continue;
    }
    if (arg === '--marker') {
      parsed.markers.push(rawArgs[i + 1]);
      i += 1;
      continue;
    }
    if (arg.startsWith('--cwd=')) {
      parsed.cwd = arg.slice('--cwd='.length);
      continue;
    }
    if (arg.startsWith('--script=')) {
      parsed.script = arg.slice('--script='.length);
      continue;
    }
    if (arg.startsWith('--proof-name=')) {
      parsed['proof-name'] = arg.slice('--proof-name='.length);
      continue;
    }
    if (arg.startsWith('--bin=')) {
      parsed.bin = arg.slice('--bin='.length);
      continue;
    }
    if (arg.startsWith('--marker=')) {
      parsed.markers.push(arg.slice('--marker='.length));
      continue;
    }
    throw new Error(`unknown argument ${arg}`);
  }
  return parsed;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const proofName = args['proof-name'];
  if (!proofName) {
    throw new Error('missing required --proof-name');
  }
  const result = runClientCommand({
    cwd: args.cwd || process.cwd(),
    script: args.script,
    bin: args.bin || 'npm',
    markers: args.markers,
  });

  if (result.output) {
    const stream = result.exitCode === 0 ? process.stdout : process.stderr;
    stream.write(result.output.endsWith('\n') ? result.output : `${result.output}\n`);
  }
  if (result.exitCode === 0) {
    console.log(`${proofName} validated: ${result.markers.join(', ')}`);
    process.exit(0);
  }
  process.exit(result.exitCode);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-client-command.mjs')) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
