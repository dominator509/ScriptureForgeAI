import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

export const goProbePackages = [
  './tools/ciprobe',
  './tools/stagingprobe',
  './tools/tenantprobe',
  './tools/rustprobe',
  './tools/observabilityprobe',
  './tools/securityprobe',
  './tools/resilienceprobe',
  './tools/mobileprobe',
  './tools/deploymentprobe',
  './tools/abuseprobe',
  './tools/zoomprobe',
  './tools/aiprobe',
  './tools/loadtest',
];

export const goProbeProofMarkers = [
  'ciprobe_tests=true',
  'stagingprobe_tests=true',
  'tenantprobe_tests=true',
  'rustprobe_tests=true',
  'observabilityprobe_tests=true',
  'securityprobe_tests=true',
  'resilienceprobe_tests=true',
  'mobileprobe_tests=true',
  'deploymentprobe_tests=true',
  'abuseprobe_tests=true',
  'zoomprobe_tests=true',
  'aiprobe_tests=true',
  'loadtest_tests=true',
  'count_one_uncached=true',
];

export function defaultGoBin(platformName = platform()) {
  return platformName === 'win32' ? '.\\.tools\\go\\bin\\go.exe' : './.tools/go/bin/go';
}

export function runGoProbeTests({
  bin,
  packages = goProbePackages,
  cwd = process.cwd(),
  spawnSyncImpl = spawnSync,
  platformName = platform(),
  env = process.env,
} = {}) {
  const command = bin || defaultGoBin(platformName);
  const args = ['test', ...packages, '-count=1'];
  const child = spawnSyncImpl(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
    env,
  });
  const output = `${child.stdout || ''}${child.stderr || ''}${child.error ? child.error.message : ''}`;
  const exitCode = child.status ?? 1;
  return {
    exitCode,
    output,
    markers: goProbeProofMarkers,
    packages,
    command,
    args,
  };
}

export function parseArgs(rawArgs) {
  const parsed = {};
  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg === '--bin' || arg === '--cwd') {
      parsed[arg.slice(2)] = rawArgs[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith('--bin=')) {
      parsed.bin = arg.slice('--bin='.length);
      continue;
    }
    if (arg.startsWith('--cwd=')) {
      parsed.cwd = arg.slice('--cwd='.length);
      continue;
    }
    throw new Error(`unknown argument ${arg}`);
  }
  return parsed;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const result = runGoProbeTests({
    bin: args.bin,
    cwd: args.cwd || process.cwd(),
  });
  if (result.output) {
    const stream = result.exitCode === 0 ? process.stdout : process.stderr;
    stream.write(result.output.endsWith('\n') ? result.output : `${result.output}\n`);
  }
  if (result.exitCode === 0) {
    console.log(`production evidence probe tests validated: ${result.markers.join(', ')}`);
    process.exit(0);
  }
  process.exit(result.exitCode);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-go-probe-tests.mjs')) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
