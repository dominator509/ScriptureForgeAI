import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const isWindows = process.platform === 'win32';
const goBin = isWindows ? '.\\.tools\\go\\bin\\go.exe' : './.tools/go/bin/go';
const cargoBin = isWindows ? '.\\.tools\\cargo\\bin\\cargo.exe' : './.tools/cargo/bin/cargo';
const terraformBin = isWindows ? '.\\.tools\\terraform\\terraform.exe' : './.tools/terraform/terraform';
const npmBin = isWindows ? 'npm.cmd' : 'npm';
const nodeBin = process.execPath;

export const gateDefinitions = [
  { id: 'go-test', command: [goBin, 'test', './...', '-count=1', '-timeout=90s'], env: { GOCACHE: '.gocache' } },
  { id: 'go-vet', command: [goBin, 'vet', './...'], env: { GOCACHE: '.gocache' } },
  { id: 'evidence-probes', command: [goBin, 'test', './tools/ciprobe', './tools/stagingprobe', './tools/tenantprobe', './tools/rustprobe', './tools/observabilityprobe', './tools/securityprobe', './tools/resilienceprobe', './tools/mobileprobe', './tools/deploymentprobe', './tools/abuseprobe', './tools/zoomprobe', './tools/aiprobe', './tools/loadtest', '-count=1'], env: { GOCACHE: '.gocache' } },
  { id: 'web-audit', command: [npmBin, 'audit', '--audit-level=moderate'], cwd: 'web' },
  { id: 'web-smoke', command: [npmBin, 'run', 'smoke'], cwd: 'web' },
  { id: 'web-typecheck', command: [npmBin, 'run', 'typecheck'], cwd: 'web' },
  { id: 'web-build', command: [npmBin, 'run', 'build'], cwd: 'web' },
  { id: 'mobile-audit', command: [npmBin, 'audit', '--audit-level=high'], cwd: 'mobile' },
  { id: 'mobile-smoke', command: [npmBin, 'run', 'smoke'], cwd: 'mobile' },
  { id: 'mobile-build-check', command: [npmBin, 'run', 'build:check'], cwd: 'mobile' },
  { id: 'rust-cargo-test', command: [cargoBin, 'test', '--manifest-path', 'services/scripture-engine/Cargo.toml'], env: { CARGO_HOME: '.tools/cargo', RUSTUP_HOME: '.tools/rustup' } },
  { id: 'terraform-fmt', command: [terraformBin, '-chdir=build/terraform', 'fmt', '-check', '-recursive'] },
  { id: 'terraform-init-validate', command: [terraformBin, '-chdir=build/terraform', 'init', '-backend=false'] },
  { id: 'terraform-validate', command: [terraformBin, '-chdir=build/terraform', 'validate'] },
  { id: 'observability-validation', command: [nodeBin, 'tools/validate-observability.mjs'] },
  { id: 'deployment-skeleton-validation', command: [nodeBin, 'tools/validate-deployment-skeleton.mjs'] },
  { id: 'staging-evidence-validation', command: [nodeBin, 'tools/validate-staging-evidence.mjs'] },
  { id: 'ci-workflow-validation', command: [nodeBin, 'tools/validate-ci-workflow.mjs'] },
  { id: 'security-artifacts-validation', command: [nodeBin, 'tools/validate-security-artifacts.mjs'] },
  { id: 'dependency-risk-validation', command: [nodeBin, 'tools/validate-dependency-risk.mjs'] },
  { id: 'secret-hygiene-validation', command: [nodeBin, 'tools/validate-secret-hygiene.mjs'] },
  { id: 'journal-crypto-validation', command: [nodeBin, 'tools/verify-journal-crypto.mjs'] },
  { id: 'tooling-tests', command: [nodeBin, '--test', 'tools/run-local-gates.test.mjs', 'tools/validate-local-gate-report.test.mjs', 'tools/validate-ci-workflow.test.mjs', 'tools/validate-dependency-risk.test.mjs', 'tools/validate-staging-evidence.test.mjs', 'tools/verify-production-readiness.test.mjs', 'tools/record-staging-evidence.test.mjs', 'tools/bootstrap-staging-evidence.test.mjs', 'tools/write-ci-release-evidence.test.mjs'] },
];

export function parseArgs(argv) {
  const args = {
    dryRun: false,
    continueOnFailure: false,
    only: [],
    report: 'artifacts/local-gate-report.json',
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--dry-run') {
      args.dryRun = true;
    } else if (argv[i] === '--continue-on-failure') {
      args.continueOnFailure = true;
    } else if (argv[i] === '--only') {
      args.only = argv[i + 1].split(',').map((value) => value.trim()).filter(Boolean);
      i += 1;
    } else if (argv[i] === '--report') {
      args.report = argv[i + 1];
      i += 1;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

export function buildGatePlan({ only = [] } = {}) {
  const selected = only.length > 0
    ? gateDefinitions.filter((gate) => only.includes(gate.id))
    : gateDefinitions;
  const selectedIds = new Set(selected.map((gate) => gate.id));
  const missing = only.filter((id) => !selectedIds.has(id));
  if (missing.length > 0) {
    throw new Error(`unknown local gate id(s): ${missing.join(', ')}`);
  }
  return selected.map((gate) => ({
    ...gate,
    display: commandDisplay(gate),
  }));
}

export async function runGatePlan(plan, { dryRun = false, continueOnFailure = false, executor = executeGate } = {}) {
  const startedAt = new Date();
  const results = [];
  for (const gate of plan) {
    const start = Date.now();
    const result = dryRun
      ? { exitCode: 0, stdout: '', stderr: '', skipped: true }
      : await executor(gate);
    const gateResult = {
      id: gate.id,
      command: gate.display,
      cwd: gate.cwd ?? '.',
      skipped: Boolean(result.skipped),
      exit_code: result.exitCode,
      duration_ms: Date.now() - start,
      stdout_tail: tail(result.stdout),
      stderr_tail: tail(result.stderr),
    };
    results.push(gateResult);
    if (result.exitCode !== 0 && !continueOnFailure) {
      break;
    }
  }

  const failed = results.filter((result) => result.exit_code !== 0);
  return {
    schema_version: 1,
    observed_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    duration_ms: Date.now() - startedAt.getTime(),
    threshold_pass: failed.length === 0 && results.length === plan.length,
    dry_run: dryRun,
    gates_total: plan.length,
    gates_run: results.length,
    gates_failed: failed.length,
    results,
  };
}

export async function writeReport(path, report) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
}

export function resolveGateForExecution(gate, workspaceRoot = process.cwd()) {
  return {
    ...gate,
    cwd: gate.cwd ? resolve(workspaceRoot, gate.cwd) : workspaceRoot,
    env: absolutizeEnvPaths(gate.env ?? {}, workspaceRoot),
  };
}

function absolutizeEnvPaths(env, workspaceRoot) {
  const pathKeys = new Set(['GOCACHE', 'CARGO_HOME', 'RUSTUP_HOME']);
  return Object.fromEntries(Object.entries(env).map(([key, value]) => {
    if (pathKeys.has(key) && value && !isAbsolutePath(value)) {
      return [key, resolve(workspaceRoot, value)];
    }
    return [key, value];
  }));
}

function isAbsolutePath(value) {
  return /^[a-zA-Z]:[\\/]/.test(value) || value.startsWith('/') || value.startsWith('\\\\');
}

export function executeGate(gate) {
  return new Promise((resolve) => {
    const executableGate = resolveGateForExecution(gate);
    const spawnPlan = buildSpawnPlan(gate.command);
    let stdout = '';
    let stderr = '';
    let child;
    try {
      child = spawn(spawnPlan.command, spawnPlan.args, {
        cwd: executableGate.cwd,
        env: { ...process.env, ...executableGate.env },
        shell: false,
      });
    } catch (error) {
      resolve({ exitCode: 1, stdout, stderr: `${stderr}${error.message}` });
      return;
    }
    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    child.on('error', (error) => {
      resolve({ exitCode: 1, stdout, stderr: `${stderr}${error.message}` });
    });
    child.on('close', (code) => {
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}

export function buildSpawnPlan(command) {
  const [program, ...args] = command;
  if (isWindowsCommandShim(program)) {
    return {
      command: process.env.ComSpec ?? 'cmd.exe',
      args: ['/d', '/s', '/c', command.map(quoteWindowsShellArg).join(' ')],
    };
  }
  return { command: program, args };
}

function isWindowsCommandShim(program) {
  return isWindows && /\.(cmd|bat)$/i.test(program);
}

function quoteWindowsShellArg(value) {
  if (/^[A-Za-z0-9_./\\:=+-]+$/.test(value)) {
    return value;
  }
  return `"${value.replaceAll('"', '\\"')}"`;
}

function commandDisplay(gate) {
  const prefix = gate.cwd ? `(cd ${gate.cwd}) ` : '';
  return `${prefix}${gate.command.join(' ')}`;
}

function tail(value, maxLength = 4000) {
  if (!value) return '';
  return value.length > maxLength ? value.slice(value.length - maxLength) : value;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const plan = buildGatePlan({ only: args.only });
  const report = await runGatePlan(plan, args);
  await writeReport(args.report, report);
  console.log(`local gate report written to ${args.report}: ${report.gates_run}/${report.gates_total} run, ${report.gates_failed} failed`);
  if (!report.threshold_pass) {
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-local-gates.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
