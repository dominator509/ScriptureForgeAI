import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildRLSDBIntegrationCommand,
  buildRLSDBIntegrationEnv,
  rlsDBProofMarkers,
  rlsDBRequiredTests,
  rlsDBSemanticProofMarkers,
  rlsDBTestPattern,
  parseArgs,
  validateRLSDBGoTestOutput,
  validateDatabaseURL,
} from './run-rls-db-integration.mjs';

test('validateDatabaseURL rejects missing or placeholder database URLs', () => {
  assert.throws(
    () => validateDatabaseURL({}),
    /DATABASE_URL is required for rls-db-integration/,
  );
  assert.throws(
    () => validateDatabaseURL({ DATABASE_URL: 'postgres://${USER}@localhost/db' }),
    /DATABASE_URL is required for rls-db-integration/,
  );
});

test('validateDatabaseURL accepts concrete postgres URLs', () => {
  assert.doesNotThrow(() => validateDatabaseURL({
    DATABASE_URL: 'postgres://postgres:scriptureforge@localhost:55433/scriptureforge?sslmode=disable',
  }));
});

test('buildRLSDBIntegrationCommand targets the required DB-backed RLS tests', () => {
  const command = buildRLSDBIntegrationCommand({ goBin: 'go' });
  assert.deepEqual(command.slice(0, 4), ['go', 'test', './tests/integration', './internal/ports']);
  assert.equal(command.includes('-v'), true);
  assert.equal(command.includes(rlsDBTestPattern), true);
  for (const marker of rlsDBRequiredTests) {
    assert.match(rlsDBTestPattern, new RegExp(marker));
  }
});

test('parseArgs accepts an explicit Go binary for CI setup-go environments', () => {
  assert.deepEqual(parseArgs(['--bin', 'go']), { goBin: 'go' });
  assert.throws(() => parseArgs(['--bin']), /requires a Go executable path/);
  assert.throws(() => parseArgs(['--unknown']), /unknown argument --unknown/);
});

test('rlsDBProofMarkers include semantic tenant isolation coverage markers', () => {
  for (const marker of rlsDBRequiredTests) {
    assert.equal(rlsDBProofMarkers.includes(marker), true);
  }
  for (const marker of [
    'rls_all_tenant_tables=true',
    'rls_table_organizations=true',
    'rls_table_users=true',
    'rls_table_scripture_texts=true',
    'rls_table_refresh_tokens=true',
    'rls_table_journal_entries=true',
    'rls_table_live_rooms=true',
    'rls_table_room_participants=true',
    'rls_table_ai_request_logs=true',
    'rls_table_citation_trails=true',
    'rls_same_tenant_reads_pass_all_tables=true',
    'rls_same_tenant_writes_pass_all_tables=true',
    'rls_same_tenant_updates_pass_all_tables=true',
    'rls_same_tenant_deletes_pass_all_tables=true',
    'rls_cross_tenant_reads_denied_all_tables=true',
    'rls_cross_tenant_inserts_denied_all_tables=true',
    'rls_cross_tenant_updates_hidden_all_tables=true',
    'rls_cross_tenant_deletes_hidden_all_tables=true',
    'rls_same_tenant_reads_pass=true',
    'rls_cross_tenant_reads_denied=true',
    'rls_cross_tenant_writes_denied=true',
    'rls_cross_tenant_updates_hidden=true',
    'rls_cross_tenant_deletes_hidden=true',
    'journal_handler_rls=true',
    'journal_handler_same_tenant_write_pass=true',
    'journal_handler_same_tenant_read_pass=true',
    'journal_handler_cross_tenant_read_denied=true',
    'journal_handler_cross_tenant_write_denied=true',
    'journal_plaintext_rejected=true',
    'room_active_handler_rls=true',
    'room_handler_same_tenant_write_pass=true',
    'room_handler_same_tenant_read_pass=true',
    'room_handler_cross_tenant_read_denied=true',
    'room_handler_cross_tenant_write_denied=true',
    'room_state_handler_rls=true',
    'room_state_handler_same_tenant_read_pass=true',
    'room_state_handler_cross_tenant_read_denied=true',
    'room_state_handler_cross_tenant_store_not_called=true',
    'room_create_tenant_override_denied=true',
    'websocket_tenant_scoping=true',
    'ai_audit_rls=true',
    'generated_curriculum_audit_rls=true',
    'auth_refresh_session_rls=true',
    'auth_mfa_rls=true',
    'workspace_switch_tenant_match=true',
    'privileged_mfa_enrollment_rls=true',
  ]) {
    assert.equal(rlsDBSemanticProofMarkers.includes(marker), true);
    assert.equal(rlsDBProofMarkers.includes(marker), true);
  }
});

test('buildRLSDBIntegrationEnv forces DB requirement and default Go cache', () => {
  const env = buildRLSDBIntegrationEnv({ DATABASE_URL: 'postgres://example' }, 'C:\\dev\\ScriptureForgeAI');
  assert.equal(env.REQUIRE_DATABASE_URL, 'true');
  assert.match(env.GOCACHE, /[\\/]?\.gocache$/);
});

test('validateRLSDBGoTestOutput accepts verbose output only when every required RLS test passed', () => {
  const output = rlsDBRequiredTests
    .map((marker) => `=== RUN   Test${marker}\n--- PASS: Test${marker} (0.01s)`)
    .join('\n');

  assert.doesNotThrow(() => validateRLSDBGoTestOutput(output));
});

test('validateRLSDBGoTestOutput rejects missing required RLS tests', () => {
  const output = rlsDBRequiredTests
    .filter((marker) => marker !== 'TenantScopedJournalHandlersEnforceRLS')
    .map((marker) => `=== RUN   Test${marker}\n--- PASS: Test${marker} (0.01s)`)
    .join('\n');

  assert.throws(
    () => validateRLSDBGoTestOutput(output),
    /must include PASS for TestTenantScopedJournalHandlersEnforceRLS/,
  );
});

test('validateRLSDBGoTestOutput rejects skipped required RLS tests', () => {
  const output = rlsDBRequiredTests
    .map((marker) => marker === 'RoomHandlersHonorTenantIsolation'
      ? `=== RUN   Test${marker}\n--- SKIP: Test${marker} (0.01s)`
      : `=== RUN   Test${marker}\n--- PASS: Test${marker} (0.01s)`)
    .join('\n');

  assert.throws(
    () => validateRLSDBGoTestOutput(output),
    /must include PASS for TestRoomHandlersHonorTenantIsolation/,
  );
});
