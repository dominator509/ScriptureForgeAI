import assert from 'node:assert/strict';
import { isAbsolute, resolve } from 'node:path';
import test from 'node:test';
import { buildGatePlan, buildSpawnPlan, gateDefinitions, parseArgs, resolveGateForExecution, runGatePlan } from './run-local-gates.mjs';

test('parseArgs supports dry run, report, continue, and only', () => {
  const args = parseArgs(['--dry-run', '--continue-on-failure', '--report', 'out.json', '--only', 'go-test,go-vet']);
  assert.equal(args.dryRun, true);
  assert.equal(args.continueOnFailure, true);
  assert.equal(args.report, 'out.json');
  assert.deepEqual(args.only, ['go-test', 'go-vet']);
});

test('buildGatePlan returns all gates by default and selected gates by id', () => {
  assert.equal(buildGatePlan().length, gateDefinitions.length);
  const selected = buildGatePlan({ only: ['go-test', 'web-build'] });
  assert.deepEqual(selected.map((gate) => gate.id), ['go-test', 'web-build']);
});

test('buildGatePlan rejects unknown gates', () => {
  assert.throws(() => buildGatePlan({ only: ['missing-gate'] }), /unknown local gate/);
});

test('resolveGateForExecution makes cwd and cache env paths absolute', () => {
  const root = resolve('/tmp/ScriptureForgeAI');
  const goGate = resolveGateForExecution(buildGatePlan({ only: ['go-test'] })[0], root);
  assert.equal(goGate.cwd, root);
  assert.equal(isAbsolute(goGate.env.GOCACHE), true);
  assert.equal(goGate.env.GOCACHE, resolve(root, '.gocache'));

  const webGate = resolveGateForExecution(buildGatePlan({ only: ['web-build'] })[0], root);
  assert.equal(webGate.cwd, resolve(root, 'web'));
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
  const report = await runGatePlan(plan, { dryRun: true });
  assert.equal(report.threshold_pass, true);
  assert.equal(report.gates_run, 2);
  assert.equal(report.results.every((result) => result.skipped), true);
});

test('runGatePlan stops on first failure unless continueOnFailure is set', async () => {
  const plan = buildGatePlan({ only: ['go-test', 'go-vet', 'web-build'] });
  const executor = async (gate) => ({
    exitCode: gate.id === 'go-vet' ? 1 : 0,
    stdout: `${gate.id} stdout`,
    stderr: `${gate.id} stderr`,
  });

  const stopped = await runGatePlan(plan, { executor });
  assert.equal(stopped.threshold_pass, false);
  assert.equal(stopped.gates_run, 2);

  const continued = await runGatePlan(plan, { executor, continueOnFailure: true });
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
