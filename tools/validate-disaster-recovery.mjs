import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export function validateDisasterRecoveryScripts(backup, restore, report) {
  for (const [source, label] of [[backup, 'backup script'], [restore, 'restore script']]) {
    assert.match(source, /set -euo pipefail/, `${label} must fail closed on shell errors`);
    assert.match(source, /pg_(dump|restore)/, `${label} must use PostgreSQL tooling`);
    assert.doesNotMatch(
      source,
      /state_wal\.log|services\/platform-engine|curl\s+-s\s+http:\/\/localhost/,
      `${label} must not use the retired mock runtime`,
    );
  }

  assert.match(backup, /DATABASE_URL/, 'backup script must require DATABASE_URL');
  assert.match(backup, /--format=custom/, 'backup script must create a portable custom archive');
  assert.match(backup, /--no-owner/, 'backup script must avoid restoring source ownership');
  assert.match(backup, /sha256sum|shasum/, 'backup script must record an integrity checksum');
  assert.match(backup, /pg_restore --list/, 'backup script must validate the archive before publishing it');
  assert.match(backup, /latest_snapshot\.info/, 'backup script must publish an explicit latest snapshot reference');

  assert.match(restore, /TARGET_DATABASE_URL/, 'restore script must require an explicit target database');
  assert.match(restore, /CONFIRM_RESTORE.*YES/, 'restore script must require explicit restore confirmation');
  assert.match(restore, /ALLOW_DESTRUCTIVE_RESTORE.*YES/, 'restore script must require explicit destructive confirmation');
  assert.match(restore, /TARGET_DATABASE_URL.*must differ from DATABASE_URL/, 'restore script must prevent source-target self-restore');
  assert.match(restore, /--clean/, 'restore script must replace existing target objects deliberately');
  assert.match(restore, /--exit-on-error/, 'restore script must stop on the first restore error');
  assert.match(restore, /sha256sum --check|shasum -a 256 --check/, 'restore script must verify the archive checksum');
  assert.match(restore, /scriptureforge-\[0-9\]\{8\}T/, 'restore script must constrain snapshot selection to generated names');

  assert.match(report, /Historical mock-sandbox documentation, not production evidence/);
  assert.match(report, /not the current PostgreSQL\/Redis\s+application/);
  assert.match(report, /DR-BACKUP-001.*DR-ROLLBACK-001/);
  assert.doesNotMatch(report, /Elite Resilience|Current State \(Post-Fix\)/);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-disaster-recovery.mjs')) {
  const [backup, restore, report] = await Promise.all([
    readFile(new URL('../scripts/disaster_recovery/backup.sh', import.meta.url), 'utf8'),
    readFile(new URL('../scripts/disaster_recovery/restore.sh', import.meta.url), 'utf8'),
    readFile(new URL('../DISASTER_RECOVERY_METRICS.md', import.meta.url), 'utf8'),
  ]);
  validateDisasterRecoveryScripts(backup, restore, report);
  console.log('disaster recovery scripts and historical evidence boundaries validated');
}
