import assert from 'node:assert/strict';
import { isAbsolute, resolve } from 'node:path';
import test from 'node:test';
import { buildGatePlan, buildSpawnPlan, gateDefinitions, parseArgs, readGitState, resolveGateForExecution, runGatePlan } from './run-local-gates.mjs';

test('parseArgs supports dry run, report, continue, and only', () => {
  const args = parseArgs(['--dry-run', '--continue-on-failure', '--report', 'out.json', '--only', 'go-test,go-vet']);
  assert.equal(args.dryRun, true);
  assert.equal(args.continueOnFailure, true);
  assert.equal(args.report, 'out.json');
  assert.deepEqual(args.only, ['go-test', 'go-vet']);
});

test('buildGatePlan returns all gates by default and selected gates by id', () => {
  assert.equal(buildGatePlan().length, gateDefinitions.length);
  const selected = buildGatePlan({ only: ['go-test', 'rls-db-integration', 'web-build'] });
  assert.deepEqual(selected.map((gate) => gate.id), ['go-test', 'rls-db-integration', 'web-build']);
  const rlsGate = selected.find((gate) => gate.id === 'rls-db-integration');
  assert.equal(rlsGate.env.REQUIRE_DATABASE_URL, 'true');
  assert.equal(rlsGate.command.some((part) => part.endsWith('tools/run-rls-db-integration-docker.mjs')), true);
  assert.match(rlsGate.display, /REQUIRE_DATABASE_URL=true/);
});

test('buildGatePlan rejects unknown gates', () => {
  assert.throws(() => buildGatePlan({ only: ['missing-gate'] }), /unknown local gate/);
});

test('buildGatePlan runs Rust tests against the committed lockfile', () => {
  const [rustGate] = buildGatePlan({ only: ['rust-cargo-test'] });
  assert.ok(rustGate.command.includes('tools/run-rust-cargo-gate.mjs'));
  assert.match(rustGate.display, /tools\/run-rust-cargo-gate\.mjs --bin/);
  assert.match(rustGate.display, /CARGO_HOME=\.tools\/cargo/);
});

test('buildGatePlan wraps Go test and vet gates with proof markers', () => {
  const [goTestGate] = buildGatePlan({ only: ['go-test'] });
  assert.ok(goTestGate.command.includes('tools/run-go-core-gate.mjs'));
  assert.match(goTestGate.display, /tools\/run-go-core-gate\.mjs --mode test --bin/);
  assert.match(goTestGate.display, /GOCACHE=\.gocache/);

  const [goVetGate] = buildGatePlan({ only: ['go-vet'] });
  assert.ok(goVetGate.command.includes('tools/run-go-core-gate.mjs'));
  assert.match(goVetGate.display, /tools\/run-go-core-gate\.mjs --mode vet --bin/);
  assert.match(goVetGate.display, /GOCACHE=\.gocache/);
});

test('buildGatePlan wraps production evidence probe tests with proof markers', () => {
  const [probeGate] = buildGatePlan({ only: ['evidence-probes'] });
  assert.ok(
    probeGate.command.includes('tools/run-go-probe-tests.mjs'),
    'evidence-probes must use the proof-marker wrapper',
  );
  assert.match(probeGate.display, /tools\/run-go-probe-tests\.mjs --bin/);
  assert.match(probeGate.display, /GOCACHE=\.gocache/);
});

test('buildGatePlan wraps Terraform fmt and validate gates with proof markers', () => {
  const [fmtGate] = buildGatePlan({ only: ['terraform-fmt'] });
  assert.ok(fmtGate.command.includes('tools/run-terraform-command.mjs'));
  assert.match(fmtGate.display, /tools\/run-terraform-command\.mjs --mode fmt --bin/);

  const [validateGate] = buildGatePlan({ only: ['terraform-validate'] });
  assert.ok(validateGate.command.includes('tools/run-terraform-command.mjs'));
  assert.match(validateGate.display, /tools\/run-terraform-command\.mjs --mode validate --bin/);
});

test('buildGatePlan includes readiness sync unit tests in the tooling gate', () => {
  const [toolingGate] = buildGatePlan({ only: ['tooling-tests'] });
  assert.ok(
    toolingGate.command.includes('tools/sync-obsidian-readiness.test.mjs'),
    'tooling-tests must cover Obsidian readiness snapshot sync behavior',
  );
  assert.ok(
    toolingGate.command.includes('tools/sync-staging-evidence-contract.test.mjs'),
    'tooling-tests must cover staging evidence contract sync behavior',
  );
  assert.ok(
    toolingGate.command.includes('tools/run-client-command.test.mjs'),
    'tooling-tests must cover client command wrapper behavior',
  );
  assert.ok(
    toolingGate.command.includes('tools/run-go-core-gate.test.mjs'),
    'tooling-tests must cover Go core gate wrapper behavior',
  );
  assert.ok(
    toolingGate.command.includes('tools/run-rust-cargo-gate.test.mjs'),
    'tooling-tests must cover Rust cargo gate wrapper behavior',
  );
  assert.ok(
    toolingGate.command.includes('tools/run-go-probe-tests.test.mjs'),
    'tooling-tests must cover production evidence probe wrapper behavior',
  );
  assert.ok(
    toolingGate.command.includes('tools/run-terraform-command.test.mjs'),
    'tooling-tests must cover Terraform command wrapper behavior',
  );
  assert.ok(
    toolingGate.command.includes('tools/verify-journal-crypto.test.mjs'),
    'tooling-tests must cover journal crypto verifier proof markers',
  );
  assert.match(toolingGate.display, /tools\/sync-obsidian-readiness\.test\.mjs/);
  assert.match(toolingGate.display, /tools\/sync-staging-evidence-contract\.test\.mjs/);
  assert.match(toolingGate.display, /tools\/run-client-command\.test\.mjs/);
  assert.match(toolingGate.display, /tools\/run-go-core-gate\.test\.mjs/);
  assert.match(toolingGate.display, /tools\/run-rust-cargo-gate\.test\.mjs/);
  assert.match(toolingGate.display, /tools\/run-go-probe-tests\.test\.mjs/);
  assert.match(toolingGate.display, /tools\/run-terraform-command\.test\.mjs/);
  assert.match(toolingGate.display, /tools\/verify-journal-crypto\.test\.mjs/);
});

test('buildGatePlan requires mobile build check to include journal crypto verifier output', () => {
  const [mobileGate] = buildGatePlan({ only: ['mobile-build-check'] });
  assert.ok(mobileGate.command.includes('--require-output'));
  assert.ok(mobileGate.command.includes('journal crypto verification passed:'));
  assert.match(mobileGate.display, /--require-output journal crypto verification passed:/);
});

test('buildGatePlan includes local and strict staging PATH readiness gates before expensive gates', () => {
  const gates = buildGatePlan();
  const localPathIndex = gates.findIndex((gate) => gate.id === 'project-path-readiness');
  const strictPathIndex = gates.findIndex((gate) => gate.id === 'strict-staging-path-readiness');
  const goTestIndex = gates.findIndex((gate) => gate.id === 'go-test');

  assert.equal(localPathIndex, 0);
  assert.equal(strictPathIndex, 1);
  assert.ok(strictPathIndex < goTestIndex, 'strict staging PATH readiness should run before expensive gates');
  assert.match(gates[strictPathIndex].command.join(' '), /--strict-staging/);
});

test('buildGatePlan checks staging evidence contract before Obsidian snapshot', () => {
  const gates = buildGatePlan();
  const contractIndex = gates.findIndex((gate) => gate.id === 'staging-evidence-contract-check');
  const obsidianIndex = gates.findIndex((gate) => gate.id === 'obsidian-readiness-snapshot-check');
  assert.ok(contractIndex >= 0, 'local gates must include staging evidence contract sync check');
  assert.ok(obsidianIndex >= 0, 'local gates must include Obsidian readiness snapshot check');
  assert.ok(contractIndex < obsidianIndex, 'contract sync should run before Obsidian snapshot validation');

  const [contractGate] = buildGatePlan({ only: ['staging-evidence-contract-check'] });
  assert.match(contractGate.display, /tools\/sync-staging-evidence-contract\.mjs --check/);
});

test('buildGatePlan includes blocker-rendering staging evidence gap report gate', () => {
  const gates = buildGatePlan();
  const validationIndex = gates.findIndex((gate) => gate.id === 'staging-evidence-validation');
  const gapReportIndex = gates.findIndex((gate) => gate.id === 'staging-evidence-gap-report');
  const obsidianIndex = gates.findIndex((gate) => gate.id === 'obsidian-readiness-snapshot-check');
  assert.ok(validationIndex >= 0, 'local gates must include staging evidence validation');
  assert.ok(gapReportIndex >= 0, 'local gates must include staging evidence gap reporting');
  assert.ok(obsidianIndex >= 0, 'local gates must include Obsidian readiness snapshot check');
  assert.ok(validationIndex < gapReportIndex, 'gap report should run after manifest validation');
  assert.ok(gapReportIndex < obsidianIndex, 'gap report should run before Obsidian snapshot validation');

  const [gapReportGate] = buildGatePlan({ only: ['staging-evidence-gap-report'] });
  assert.match(gapReportGate.display, /tools\/report-staging-evidence-gaps\.mjs/);
  assert.match(gapReportGate.display, /--manifest production-readiness\/staging-evidence\.example\.json/);
  assert.match(gapReportGate.display, /--contract-manifest production-readiness\/staging-evidence\.example\.json/);
  assert.match(gapReportGate.display, /--allow-blockers/);
});

test('resolveGateForExecution makes cwd and cache env paths absolute', () => {
  const root = resolve('/tmp/ScriptureForgeAI');
  const goGate = resolveGateForExecution(buildGatePlan({ only: ['go-test'] })[0], root);
  assert.equal(goGate.cwd, root);
  assert.equal(isAbsolute(goGate.env.GOCACHE), true);
  assert.equal(goGate.env.GOCACHE, resolve(root, '.gocache'));

  const webSmokeGate = resolveGateForExecution(buildGatePlan({ only: ['web-smoke'] })[0], root);
  assert.equal(webSmokeGate.cwd, resolve(root, 'web'));

  const webBuildGate = resolveGateForExecution(buildGatePlan({ only: ['web-build'] })[0], root);
  assert.equal(webBuildGate.cwd, root);
  assert.match(webBuildGate.command.join(' '), /--cwd web/);
});

test('buildSpawnPlan launches Windows command shims through cmd', () => {
  const originalComSpec = process.env.ComSpec;
  process.env.ComSpec = 'C:\\Windows\\System32\\cmd.exe';
  try {
    const plan = buildSpawnPlan(['npm.cmd', 'run', 'build']);
    if (process.platform === 'win32') {
      assert.equal(plan.command, 'C:\\Windows\\System32\\cmd.exe');
      assert.deepEqual(plan.args, ['/d', '/s', '/c', 'npm.cmd run build']);
    } else {
      assert.equal(plan.command, 'npm.cmd');
      assert.deepEqual(plan.args, ['run', 'build']);
    }
  } finally {
    if (originalComSpec === undefined) {
      delete process.env.ComSpec;
    } else {
      process.env.ComSpec = originalComSpec;
    }
  }
});

test('runGatePlan dry run reports every gate as skipped and passing', async () => {
  const plan = buildGatePlan({ only: ['go-test', 'go-vet'] });
  const report = await runGatePlan(plan, { dryRun: true, gitStateReader: fakeGitState });
  assert.equal(report.threshold_pass, true);
  assert.equal(report.gates_run, 2);
  assert.equal(report.results.every((result) => result.skipped), true);
  assert.equal(report.git_remote_refreshed, true);
});

test('runGatePlan stops on first failure unless continueOnFailure is set', async () => {
  const plan = buildGatePlan({ only: ['go-test', 'go-vet', 'web-build'] });
  const executor = async (gate) => ({
    exitCode: gate.id === 'go-vet' ? 1 : 0,
    stdout: `${gate.id} stdout`,
    stderr: `${gate.id} stderr`,
  });

  const stopped = await runGatePlan(plan, { executor, gitStateReader: fakeGitState });
  assert.equal(stopped.threshold_pass, false);
  assert.equal(stopped.gates_run, 2);

  const continued = await runGatePlan(plan, { executor, continueOnFailure: true, gitStateReader: fakeGitState });
  assert.equal(continued.threshold_pass, false);
  assert.equal(continued.gates_run, 3);
  assert.equal(continued.gates_failed, 1);
});

test('runGatePlan records synchronous executor failures as failed gates', async () => {
  const plan = buildGatePlan({ only: ['web-audit', 'web-smoke'] });
  const executor = async (gate) => {
    if (gate.id === 'web-audit') {
      throw new Error('spawn EINVAL');
    }
    return { exitCode: 0, stdout: '', stderr: '' };
  };

  const report = await runGatePlan(plan, {
    continueOnFailure: true,
    gitStateReader: fakeGitState,
    executor: async (gate) => {
      try {
        return await executor(gate);
      } catch (error) {
        return { exitCode: 1, stdout: '', stderr: error.message };
      }
    },
  });

  assert.equal(report.threshold_pass, false);
  assert.equal(report.gates_run, 2);
  assert.equal(report.gates_failed, 1);
  assert.match(report.results[0].stderr_tail, /spawn EINVAL/);
});

test('readGitState refreshes remote metadata before reading ahead behind counts', () => {
  const calls = [];
  const state = readGitState({
    git: (args) => {
      calls.push(args.join(' '));
      if (args.join(' ') === 'fetch --dry-run') return '';
      if (args.join(' ') === 'status --short') return '';
      if (args.join(' ') === 'branch --show-current') return 'codex/production-readiness-remediation\n';
      if (args.join(' ') === 'rev-parse HEAD') return '0123456789abcdef0123456789abcdef01234567\n';
      throw new Error(`unexpected git args ${args.join(' ')}`);
    },
    optionalGit: (args) => {
      calls.push(args.join(' '));
      if (args.join(' ') === 'rev-parse --abbrev-ref --symbolic-full-name @{upstream}') {
        return 'origin/codex/production-readiness-remediation';
      }
      if (args.join(' ') === 'rev-list --left-right --count HEAD...origin/codex/production-readiness-remediation') {
        return '0\t0';
      }
      return '';
    },
  });

  assert.equal(calls[0], 'fetch --dry-run');
  assert.equal(state.git_remote_refreshed, true);
  assert.equal(state.git_ahead, 0);
  assert.equal(state.git_behind, 0);
});

test('readGitState rejects unrefreshable remote metadata', () => {
  assert.throws(
    () => readGitState({
      git: (args) => {
        if (args.join(' ') === 'fetch --dry-run') {
          throw new Error('network unavailable');
        }
        return '';
      },
      optionalGit: () => '',
    }),
    /git fetch --dry-run must succeed before writing local gate report: network unavailable/,
  );
});

function fakeGitState() {
  return {
    git_head: '0123456789abcdef0123456789abcdef01234567',
    git_branch: 'codex/production-readiness-remediation',
    git_upstream: 'origin/codex/production-readiness-remediation',
    git_ahead: 0,
    git_behind: 0,
    git_remote_refreshed: true,
    git_status_clean: true,
    git_status_short: '',
  };
}
