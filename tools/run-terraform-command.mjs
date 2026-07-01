import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

export const terraformFmtProofMarkers = [
  'terraform_fmt_command=true',
  'recursive_fmt_check=true',
  'terraform_chdir_build_terraform=true',
];

export const terraformValidateProofMarkers = [
  'terraform_validate_command=true',
  'terraform_chdir_build_terraform=true',
  'validated_skeleton=true',
  'terraform_validate_success_output=true',
];

export function defaultTerraformBin(platformName = platform()) {
  return platformName === 'win32'
    ? '.\\.tools\\terraform\\terraform.exe'
    : './.tools/terraform/terraform';
}

export function terraformArgsForMode(mode) {
  if (mode === 'fmt') {
    return {
      args: ['-chdir=build/terraform', 'fmt', '-check', '-recursive'],
      proofName: 'terraform-fmt-gate',
      markers: terraformFmtProofMarkers,
    };
  }
  if (mode === 'validate') {
    return {
      args: ['-chdir=build/terraform', 'validate'],
      proofName: 'terraform-validate-gate',
      markers: terraformValidateProofMarkers,
    };
  }
  throw new Error(`unsupported Terraform gate mode ${mode || '<empty>'}`);
}

export function runTerraformCommand({
  mode,
  bin,
  cwd = process.cwd(),
  spawnSyncImpl = spawnSync,
  platformName = platform(),
} = {}) {
  const command = bin || defaultTerraformBin(platformName);
  const plan = terraformArgsForMode(mode);
  const child = spawnSyncImpl(command, plan.args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
  });
  const output = `${child.stdout || ''}${child.stderr || ''}${child.error ? child.error.message : ''}`;
  let exitCode = child.status ?? 1;
  let validatedOutput = output;
  if (exitCode === 0 && mode === 'validate' && !stripAnsi(output).includes('Success! The configuration is valid.')) {
    const suffix = output.endsWith('\n') || output.length === 0 ? '' : '\n';
    exitCode = 1;
    validatedOutput = `${output}${suffix}terraform-validate-gate missing Terraform success output\n`;
  }
  return {
    exitCode,
    output: validatedOutput,
    command,
    args: plan.args,
    proofName: plan.proofName,
    markers: plan.markers,
  };
}

function stripAnsi(value) {
  return value.replace(/\x1B\[[0-9;]*m/g, '');
}

export function parseArgs(rawArgs) {
  const parsed = {};
  for (let i = 0; i < rawArgs.length; i += 1) {
    const arg = rawArgs[i];
    if (arg === '--mode' || arg === '--bin' || arg === '--cwd') {
      parsed[arg.slice(2)] = rawArgs[i + 1];
      i += 1;
      continue;
    }
    if (arg.startsWith('--mode=')) {
      parsed.mode = arg.slice('--mode='.length);
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
  const result = runTerraformCommand({
    mode: args.mode,
    bin: args.bin,
    cwd: args.cwd || process.cwd(),
  });
  if (result.output) {
    const stream = result.exitCode === 0 ? process.stdout : process.stderr;
    stream.write(result.output.endsWith('\n') ? result.output : `${result.output}\n`);
  }
  if (result.exitCode === 0) {
    console.log(`${result.proofName} validated: ${result.markers.join(', ')}`);
    process.exit(0);
  }
  process.exit(result.exitCode);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-terraform-command.mjs')) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
