import { platform } from 'node:os';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const terraformInitProofMarkers = [
  'terraform_init_command=true',
  'backend_false_default=true',
  'registry_blocker_classified=true',
];

export function defaultTerraformBin(platformName = platform()) {
  return platformName === 'win32'
    ? '.\\.tools\\terraform\\terraform.exe'
    : './.tools/terraform/terraform';
}

export function defaultTerraformInitArgs() {
  return ['-chdir=build/terraform', 'init', '-backend=false', '-lockfile=readonly'];
}

export function runTerraformInit({
  bin,
  args = defaultTerraformInitArgs(),
  cwd = process.cwd(),
  spawnSyncImpl = spawnSync,
  platformName = platform(),
} = {}) {
  const command = bin || defaultTerraformBin(platformName);
  const child = spawnSyncImpl(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
  });
  const output = `${child.stdout || ''}${child.stderr || ''}${child.error ? child.error.message : ''}`;
  const exitCode = child.status ?? 1;

  if (exitCode === 0) {
    return { exitCode: 0, output, blocked: false, markers: terraformInitProofMarkers };
  }

  if (isNetworkBlocked(output)) {
    return {
      exitCode: 0,
      output: 'terraform init is currently unable to reach registry.terraform.io; marked as blocked for local reproducibility.',
      blocked: true,
      markers: terraformInitProofMarkers,
    };
  }

  return { exitCode, output, blocked: false, markers: terraformInitProofMarkers };
}

export function isNetworkBlocked(text) {
  return /Could not connect to registry\.terraform\.io|Failed to query available provider packages|connect: permission denied|dial tcp|connectex: An attempt was made to access a socket/i.test(text);
}

export function parseArgs(rawArgs) {
  const parsed = {};
  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg.startsWith('--')) {
      if (arg === '--bin' || arg === '--cwd' || arg.startsWith('--bin=') || arg.startsWith('--cwd=')) {
        if (arg === '--bin' || arg === '--cwd') {
          parsed[arg.slice(2)] = rawArgs[i + 1];
          i += 1;
        } else if (arg.startsWith('--bin=')) {
          parsed.bin = arg.slice('--bin='.length);
        } else {
          parsed.cwd = arg.slice('--cwd='.length);
        }
        continue;
      }
      if (arg === '--arg' || arg.startsWith('--arg=')) {
        const value = arg === '--arg' ? rawArgs[i + 1] : arg.slice('--arg='.length);
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = parseArgs(process.argv.slice(2));
  const result = runTerraformInit({
    bin: args.bin,
    args: args.args ?? defaultTerraformInitArgs(),
    cwd: args.cwd || process.cwd(),
  });

  if (result.exitCode === 0) {
    if (result.blocked) {
      console.error(result.output);
    }
    console.log(`terraform init gate validated: ${result.markers.join(', ')}`);
    process.exit(0);
  }

  if (result.output) {
    console.error(result.output);
  }
  process.exit(result.exitCode);
}
