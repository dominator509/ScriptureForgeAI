import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { validateDisasterRecoveryScripts } from './validate-disaster-recovery.mjs';

async function fixtures() {
  return Promise.all([
    readFile('scripts/disaster_recovery/backup.sh', 'utf8'),
    readFile('scripts/disaster_recovery/restore.sh', 'utf8'),
    readFile('DISASTER_RECOVERY_METRICS.md', 'utf8'),
  ]);
}

test('current disaster recovery helpers use the PostgreSQL recovery boundary', async () => {
  const currentFixtures = await fixtures();
  assert.doesNotThrow(() => validateDisasterRecoveryScripts(...currentFixtures));
});

test('disaster recovery validation rejects the retired WAL mock', async () => {
  const [backup, restore, report] = await fixtures();
  const broken = backup.replace('pg_dump', 'cp').concat('\nservices/platform-engine/state_wal.log\n');
  assert.throws(
    () => validateDisasterRecoveryScripts(broken, restore, report),
    /backup script must use PostgreSQL tooling|backup script must not use the retired mock runtime/,
  );
});

test('disaster recovery validation rejects historical reports that claim production proof', async () => {
  const [backup, restore, report] = await fixtures();
  const broken = report.replace('not production evidence', 'production evidence').replace('Historical mock-sandbox', 'Elite Resilience');
  assert.throws(
    () => validateDisasterRecoveryScripts(backup, restore, broken),
    /not production evidence|Elite Resilience|Current State/,
  );
});
