import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export function validateDependencyRisk({ lockfile, register }) {
  const uuidVersion = packageVersion(lockfile, 'node_modules/uuid');
  const expoVersion = packageVersion(lockfile, 'node_modules/expo');
  assert.ok(uuidVersion, 'mobile package lock must include node_modules/uuid while DRR-001 is tracked');
  assert.ok(expoVersion, 'mobile package lock must include node_modules/expo while DRR-001 is tracked');

  const uuidIsStillRisk = compareSemver(uuidVersion, '11.1.1') < 0;
  if (uuidIsStillRisk) {
    for (const snippet of requiredDRR001Snippets(uuidVersion, expoVersion)) {
      assert.ok(register.includes(snippet), `dependency risk register missing ${snippet}`);
    }
  } else {
    assert.ok(!register.includes('DRR-001'), `DRR-001 should be closed because locked uuid ${uuidVersion} is >= 11.1.1`);
  }

  return {
    uuidVersion,
    expoVersion,
    drr001Required: uuidIsStillRisk,
  };
}

function packageVersion(lockfile, packagePath) {
  return lockfile.packages?.[packagePath]?.version ?? '';
}

function requiredDRR001Snippets(uuidVersion, expoVersion) {
  return [
    '## DRR-001',
    'uuid <11.1.1',
    `expo@${expoVersion}`,
    `uuid@${uuidVersion}`,
    'GHSA-w5hq-g745-h8pq',
    'Severity: Moderate',
    'Current result: `npm audit --audit-level=high` passes, but reports 10 moderate findings.',
    'Current moderate audit recheck:',
    'reports 10 moderate findings, 0 high, and 0 critical',
    'Dry-run remediation recheck:',
    'reports `changed: 0`',
    'expo@46.0.21',
    'Risk decision: Accepted temporarily',
    'high-or-worse audit gating is enforced in CI',
    'Required closure',
    'uuid >=11.1.1',
  ];
}

export function compareSemver(left, right) {
  const a = parseVersion(left);
  const b = parseVersion(right);
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

function parseVersion(value) {
  const match = value.match(/^(\d+)\.(\d+)\.(\d+)/);
  assert.ok(match, `unsupported semver value ${value}`);
  return match.slice(1).map(Number);
}

async function main() {
  const [lockfilePath = 'mobile/package-lock.json', registerPath = 'security/dependency_risk_register.md'] = process.argv.slice(2);
  const lockfile = JSON.parse(await readFile(lockfilePath, 'utf8'));
  const register = await readFile(registerPath, 'utf8');
  const result = validateDependencyRisk({ lockfile, register });
  console.log(`dependency risk validated: uuid ${result.uuidVersion}, expo ${result.expoVersion}, DRR-001 required=${result.drr001Required}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-dependency-risk.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
