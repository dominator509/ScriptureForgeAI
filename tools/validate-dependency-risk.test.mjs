import assert from 'node:assert/strict';
import test from 'node:test';
import { compareSemver, validateDependencyRisk } from './validate-dependency-risk.mjs';

test('compareSemver compares major, minor, and patch versions', () => {
  assert.ok(compareSemver('7.0.3', '11.1.1') < 0);
  assert.ok(compareSemver('11.1.1', '11.1.1') === 0);
  assert.ok(compareSemver('12.0.0', '11.1.1') > 0);
});

test('validateDependencyRisk accepts precise DRR-001 while uuid remains vulnerable', () => {
  const result = validateDependencyRisk({
    lockfile: lockfile('7.0.3', '56.0.12'),
    register: register('7.0.3', '56.0.12'),
  });

  assert.equal(result.uuidVersion, '7.0.3');
  assert.equal(result.expoVersion, '56.0.12');
  assert.equal(result.drr001Required, true);
});

test('validateDependencyRisk rejects stale DRR-001 after uuid remediation', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('11.1.1', '56.0.12'),
      register: register('7.0.3', '56.0.12'),
    }),
    /should be closed/,
  );
});

test('validateDependencyRisk rejects incomplete DRR-001 details', () => {
  assert.throws(
    () => validateDependencyRisk({
      lockfile: lockfile('7.0.3', '56.0.12'),
      register: '## DRR-001\nuuid <11.1.1\n',
    }),
    /missing expo@56.0.12/,
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
- Risk decision: Accepted temporarily because high-or-worse audit gating is enforced in CI.
- Required closure: Remove this accepted risk when Expo resolves uuid >=11.1.1.
`;
}
