import assert from 'node:assert/strict';
import test from 'node:test';
import { compareSemver, validateDependencyRisk, validateNoRuntimeUUIDImports } from './validate-dependency-risk.mjs';

test('compareSemver compares major, minor, and patch versions', () => {
  assert.ok(compareSemver('7.0.3', '11.1.1') < 0);
  assert.ok(compareSemver('11.1.1', '11.1.1') === 0);
  assert.ok(compareSemver('12.0.0', '11.1.1') > 0);
});

test('validateDependencyRisk accepts precise DRR-001 while uuid remains vulnerable', () => {
  const result = validateDependencyRisk({
    lockfile: lockfile('7.0.3', '56.0.17'),
    register: register('7.0.3', '56.0.17'),
    today: '2026-06-27',
  });

  assert.equal(result.uuidVersion, '7.0.3');
  assert.equal(result.expoVersion, '56.0.17');
  assert.equal(result.drr001Required, true);
});

test('validateDependencyRisk rejects stale DRR-001 after uuid remediation', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('11.1.1', '56.0.17'),
      register: register('7.0.3', '56.0.17'),
      today: '2026-06-27',
    }),
    /should be closed/,
  );
});

test('validateDependencyRisk rejects incomplete DRR-001 details', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('7.0.3', '56.0.17'),
      register: '## DRR-001\nuuid <11.1.1\n',
      today: '2026-06-27',
    }),
    /missing expo@56.0.17/,
  );
});

test('validateDependencyRisk rejects expired DRR-001 accepted risk', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('7.0.3', '56.0.17'),
      register: register('7.0.3', '56.0.17'),
      today: '2026-08-26',
    }),
    /DRR-001 accepted risk expired on 2026-08-25/,
  );
});

test('validateDependencyRisk rejects overdue DRR-001 review before expiry', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('7.0.3', '56.0.17'),
      register: register('7.0.3', '56.0.17'),
      today: '2026-07-26',
    }),
    /DRR-001 accepted risk review is overdue as of 2026-07-25/,
  );
});

test('validateDependencyRisk rejects DRR-001 review dates after expiry', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('7.0.3', '56.0.17'),
      register: register('7.0.3', '56.0.17').replace('Review due: 2026-07-25', 'Review due: 2026-09-01'),
      today: '2026-06-27',
    }),
    /DRR-001 Review due must be on or before Expires/,
  );
});

test('validateDependencyRisk rejects uuid imports from mobile runtime while DRR-001 is accepted', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('7.0.3', '56.0.17'),
      register: register('7.0.3', '56.0.17'),
      runtimeSources: [{ path: 'mobile/src/lib/runtime.ts', content: 'import { v4 } from "uuid";' }],
      today: '2026-06-27',
    }),
    /mobile runtime source imports uuid/,
  );
});

test('validateNoRuntimeUUIDImports rejects dynamic uuid imports', () => {
  assert.throws(
    () => validateNoRuntimeUUIDImports([
      { path: 'mobile/src/lib/runtime.ts', content: 'const uuid = await import("uuid");' },
    ]),
    /mobile runtime source imports uuid/,
  );
});

function lockfile(uuidVersion, expoVersion) {
  return {
    packages: {
      'node_modules/uuid': { version: uuidVersion },
      'node_modules/expo': { version: expoVersion },
    },
  };
}

function register(uuidVersion, expoVersion) {
  return `
## DRR-001: Expo tooling transitive \`uuid <11.1.1\` advisory

- Scope: mobile/package-lock.json
- Current locked versions: expo@${expoVersion}, uuid@${uuidVersion}
- Advisory: GHSA-w5hq-g745-h8pq
- Severity: Moderate
- Current result: \`npm audit --audit-level=high\` passes, but reports 10 moderate findings.
- Current moderate audit recheck: \`npm.cmd audit --audit-level=moderate --json --cache C:\\dev\\ScriptureForgeAI\\.npm-cache\` on 2026-06-25 reports 10 moderate findings, 0 high, and 0 critical.
- Dry-run remediation recheck: \`npm.cmd audit fix --package-lock-only --dry-run --json --cache C:\\dev\\ScriptureForgeAI\\.npm-cache\` on 2026-06-25 reports \`changed: 0\` and keeps the same \`expo@46.0.21\` semver-major fix recommendation.
- Risk decision: Accepted temporarily because high-or-worse audit gating is enforced in CI.
- Risk owner: Security/release owner
- Accepted by: Release owner and security reviewer
- Review due: 2026-07-25
- Expires: 2026-08-25
- Required closure: Remove this accepted risk when Expo resolves uuid >=11.1.1.
- Release gate: Final production-readiness validation must fail if this accepted risk is expired or if the review due date has passed without a refreshed decision.
`;
}
