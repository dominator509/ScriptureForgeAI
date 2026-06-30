import { execFileSync, spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const isWindows = process.platform === 'win32';
const goBin = isWindows ? '.\\.tools\\go\\bin\\go.exe' : './.tools/go/bin/go';
const cargoBin = isWindows ? '.\\.tools\\cargo\\bin\\cargo.exe' : './.tools/cargo/bin/cargo';
const terraformBin = isWindows ? '.\\.tools\\terraform\\terraform.exe' : './.tools/terraform/terraform';
const npmBin = isWindows ? 'npm.cmd' : 'npm';
const nodeBin = process.execPath;

export const gateDefinitions = [
  { id: 'project-path-readiness', command: [nodeBin, 'tools/verify-project-path.mjs'] },
  { id: 'strict-staging-path-readiness', command: [nodeBin, 'tools/verify-project-path.mjs', '--strict-staging'] },
  { id: 'go-test', command: [nodeBin, 'tools/run-go-core-gate.mjs', '--mode', 'test', '--bin', goBin], env: { GOCACHE: '.gocache' } },
  { id: 'go-vet', command: [nodeBin, 'tools/run-go-core-gate.mjs', '--mode', 'vet', '--bin', goBin], env: { GOCACHE: '.gocache' } },
  { id: 'rls-db-integration', command: [nodeBin, 'tools/run-rls-db-integration-docker.mjs'], env: { GOCACHE: '.gocache', REQUIRE_DATABASE_URL: 'true' } },
  { id: 'evidence-probes', command: [nodeBin, 'tools/run-go-probe-tests.mjs', '--bin', goBin], env: { GOCACHE: '.gocache' } },
  { id: 'web-audit', command: [nodeBin, 'tools/run-npm-audit.mjs', '--cwd', 'web', '--level', 'moderate', '--bin', npmBin] },
  { id: 'web-smoke', command: [npmBin, 'run', 'smoke'], cwd: 'web' },
  { id: 'web-typecheck', command: [nodeBin, 'tools/run-client-command.mjs', '--cwd', 'web', '--script', 'typecheck', '--proof-name', 'web-typecheck-gate', '--marker', 'web_typescript_no_emit=true', '--marker', 'web_runtime_types=true', '--bin', npmBin] },
  { id: 'web-build', command: [nodeBin, 'tools/run-client-command.mjs', '--cwd', 'web', '--script', 'build', '--proof-name', 'web-build-gate', '--marker', 'next_build=true', '--marker', 'web_production_bundle=true', '--bin', npmBin] },
  { id: 'mobile-audit', command: [nodeBin, 'tools/run-npm-audit.mjs', '--cwd', 'mobile', '--level', 'high', '--bin', npmBin] },
  { id: 'mobile-smoke', command: [npmBin, 'run', 'smoke'], cwd: 'mobile' },
  { id: 'mobile-build-check', command: [nodeBin, 'tools/run-client-command.mjs', '--cwd', 'mobile', '--script', 'build:check', '--proof-name', 'mobile-build-check-gate', '--marker', 'mobile_typecheck=true', '--marker', 'mobile_smoke=true', '--marker', 'mobile_crypto_verification=true', '--bin', npmBin] },
  { id: 'rust-protobuf-validation', command: [nodeBin, 'tools/verify-rust-protobuf.mjs'] },
  { id: 'rust-cargo-test', command: [cargoBin, 'test', '--locked', '--manifest-path', 'services/scripture-engine/Cargo.toml'], env: { CARGO_HOME: '.tools/cargo', RUSTUP_HOME: '.tools/rustup' } },
  { id: 'terraform-fmt', command: [nodeBin, 'tools/run-terraform-command.mjs', '--mode', 'fmt', '--bin', terraformBin] },
  { id: 'terraform-init-validate', command: [nodeBin, 'tools/run-terraform-init.mjs', '--bin', terraformBin, '--arg', '-chdir=build/terraform', '--arg', 'init', '--arg', '-backend=false'] },
  { id: 'terraform-validate', command: [nodeBin, 'tools/run-terraform-command.mjs', '--mode', 'validate', '--bin', terraformBin] },
  { id: 'observability-validation', command: [nodeBin, 'tools/validate-observability.mjs'] },
  { id: 'rls-schema-validation', command: [nodeBin, 'tools/validate-rls-schema.mjs'] },
  { id: 'deployment-skeleton-validation', command: [nodeBin, 'tools/validate-deployment-skeleton.mjs'] },
  { id: 'staging-evidence-validation', command: [nodeBin, 'tools/validate-staging-evidence.mjs'] },
  { id: 'staging-evidence-gap-report', command: [nodeBin, 'tools/report-staging-evidence-gaps.mjs', '--manifest', 'production-readiness/staging-evidence.example.json', '--contract-manifest', 'production-readiness/staging-evidence.example.json', '--allow-blockers'] },
  { id: 'ci-workflow-validation', command: [nodeBin, 'tools/validate-ci-workflow.mjs'] },
  { id: 'ci-evidence-gate-validation', command: [nodeBin, 'tools/validate-ci-evidence-gates.mjs'] },
  { id: 'security-artifacts-validation', command: [nodeBin, 'tools/validate-security-artifacts.mjs'] },
  { id: 'dependency-risk-validation', command: [nodeBin, 'tools/validate-dependency-risk.mjs'] },
  { id: 'secret-hygiene-validation', command: [nodeBin, 'tools/validate-secret-hygiene.mjs'] },
  { id: 'journal-crypto-validation', command: [nodeBin, 'tools/verify-journal-crypto.mjs'] },
  { id: 'serena-obsidian-validation', command: [nodeBin, 'tools/validate-serena-obsidian.mjs'] },
  { id: 'staging-evidence-contract-check', command: [nodeBin, 'tools/sync-staging-evidence-contract.mjs', '--check'] },
  { id: 'obsidian-readiness-snapshot-check', command: [nodeBin, 'tools/sync-obsidian-readiness.mjs', '--check'] },
  { id: 'tooling-tests', command: [nodeBin, '--test', 'tools/run-local-gates.test.mjs', 'tools/run-client-command.test.mjs', 'tools/run-go-core-gate.test.mjs', 'tools/run-go-probe-tests.test.mjs', 'tools/run-npm-audit.test.mjs', 'tools/run-terraform-command.test.mjs', 'tools/run-terraform-init.test.mjs', 'tools/run-rls-db-integration.test.mjs', 'tools/run-rls-db-integration-docker.test.mjs', 'tools/validate-local-gate-report.test.mjs', 'tools/validate-ci-workflow.test.mjs', 'tools/validate-ci-evidence-gates.test.mjs', 'tools/validate-deployment-skeleton.test.mjs', 'tools/validate-rls-schema.test.mjs', 'tools/validate-observability.test.mjs', 'tools/validate-dependency-risk.test.mjs', 'tools/validate-security-artifacts.test.mjs', 'tools/validate-secret-hygiene.test.mjs', 'tools/validate-staging-evidence.test.mjs', 'tools/verify-journal-crypto.test.mjs', 'tools/verify-production-readiness.test.mjs', 'tools/record-staging-evidence.test.mjs', 'tools/bootstrap-staging-evidence.test.mjs', 'tools/report-staging-evidence-gaps.test.mjs', 'tools/sync-staging-evidence-contract.test.mjs', 'tools/sync-obsidian-readiness.test.mjs', 'tools/write-ci-release-evidence.test.mjs', 'tools/verify-rust-protobuf.test.mjs', 'tools/verify-project-path.test.mjs'] },
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
    ...readGitState(),
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

function readGitHead() {
  return execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}

function readGitState() {
  const statusShort = execFileSync('git', ['status', '--short'], { encoding: 'utf8' }).trimEnd();
  const branch = execFileSync('git', ['branch', '--show-current'], { encoding: 'utf8' }).trim();
  const upstream = readOptionalGit(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{upstream}']);
  let ahead = 0;
  let behind = 0;
  if (upstream) {
    const divergence = readOptionalGit(['rev-list', '--left-right', '--count', `HEAD...${upstream}`]);
    const [left, right] = divergence.split(/\s+/).map((value) => Number.parseInt(value, 10));
    ahead = Number.isFinite(left) ? left : 0;
    behind = Number.isFinite(right) ? right : 0;
  }
  return {
    git_head: readGitHead(),
    git_branch: branch,
    git_upstream: upstream,
    git_ahead: ahead,
    git_behind: behind,
    git_status_clean: statusShort === '',
    git_status_short: statusShort,
  };
}

function readOptionalGit(args) {
  try {
    return execFileSync('git', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
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
  const envPrefix = gate.env
    ? `${Object.entries(gate.env).map(([key, value]) => `${key}=${value}`).join(' ')} `
    : '';
  return `${prefix}${envPrefix}${gate.command.join(' ')}`;
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
