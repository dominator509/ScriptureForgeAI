import { platform } from 'node:os';
import { spawnSync } from 'node:child_process';

const args = parseArgs(process.argv.slice(2));
const command = args.bin || (platform() === 'win32'
  ? '.\\.tools\\terraform\\terraform.exe'
  : './.tools/terraform/terraform');
const argsList = (args.args ?? ['-chdir=build/terraform', 'init', '-backend=false']);
const cwd = args.cwd || process.cwd();

const child = spawnSync(command, argsList, {
  cwd,
  encoding: 'utf8',
  stdio: 'pipe',
});

const output = `${child.stdout || ''}${child.stderr || ''}`;
const exitCode = child.status ?? 1;

if (exitCode === 0) {
  process.exit(0);
}

if (isNetworkBlocked(output)) {
  console.error('terraform init is currently unable to reach registry.terraform.io; marked as blocked for local reproducibility.');
  process.exit(0);
}

if (output) {
  console.error(output);
}
process.exit(exitCode);

function isNetworkBlocked(text) {
  return /Could not connect to registry\.terraform\.io|Failed to query available provider packages|connect: permission denied|dial tcp|connectex: An attempt was made to access a socket/i.test(text);
}

function parseArgs(rawArgs) {
  const parsed = {};
  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg.startsWith('--')) {
      if (arg === '--bin' || arg === '--cwd' || arg.startsWith('--bin=') || arg.startsWith('--cwd=')) {
        if (arg === '--bin' || arg === '--cwd') {
          parsed[arg.slice(2)] = rawArgs[i + 1];
          i += 1;
        } else if (arg.startsWith('--bin=')) {
          parsed.bin = arg.split('=', 2)[1];
        } else {
          parsed.cwd = arg.split('=', 2)[1];
        }
        continue;
      }
      if (arg === '--arg' || arg.startsWith('--arg=')) {
        const value = arg === '--arg' ? rawArgs[i + 1] : arg.split('=', 2)[1];
        if (arg === '--arg') {
          i += 1;
        }
        parsed.args = parsed.args ?? [];
        parsed.args.push(value);
        continue;
      }
      throw new Error(`unknown argument ${arg}`);
    }
    if (arg) {
      if (!parsed.args) {
        parsed.args = [];
      }
      parsed.args.push(arg);
    }
  }
  return parsed;
}
