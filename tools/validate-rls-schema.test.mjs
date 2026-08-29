import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { discoverTenantScopedTables, validateProductionRoomMembershipWiring, validateRLSSchema } from './validate-rls-schema.mjs';

async function fixtures() {
  const [
    migrationText,
    tableRLSTestText,
    handlerRLSTestText,
    portHandlerRLSTestText,
    aiAuditRLSTestText,
    authSessionRLSTestText,
    authHandlerText,
    platformMainText,
    roomHandlerText,
    socketHandlerText,
    zoomWebhookText,
    zoomRoomStateMigrationText,
  ] = await Promise.all([
    readFile('migrations/000002_core_schema.up.sql', 'utf8'),
    readFile('tests/integration/table_rls_test.go', 'utf8'),
    readFile('tests/integration/tenant_handler_rls_test.go', 'utf8'),
    readFile('internal/ports/tenant_isolation_integration_test.go', 'utf8'),
    readFile('internal/ports/ai_audit_integration_test.go', 'utf8'),
    readFile('tests/integration/auth_session_test.go', 'utf8'),
    readFile('internal/ports/auth_http.go', 'utf8'),
    readFile('cmd/platform-engine/main.go', 'utf8'),
    readFile('internal/ports/rooms_http.go', 'utf8'),
    readFile('internal/ports/driving_wss.go', 'utf8'),
    readFile('internal/adapters/integration_zoom/zoom_webhook.go', 'utf8'),
    readFile('migrations/000009_zoom_webhook_room_state.up.sql', 'utf8'),
  ]);
  return {
    migrationText,
    tableRLSTestText,
    handlerRLSTestText,
    portHandlerRLSTestText,
    aiAuditRLSTestText,
    authSessionRLSTestText,
    authHandlerText,
    platformMainText,
    roomHandlerText,
    socketHandlerText,
    zoomWebhookText,
    zoomRoomStateMigrationText,
  };
}

test('validateRLSSchema accepts current tenant-scoped schema and integration tests', async () => {
  const {
    migrationText,
    tableRLSTestText,
    handlerRLSTestText,
    portHandlerRLSTestText,
    aiAuditRLSTestText,
    authSessionRLSTestText,
    authHandlerText,
    platformMainText,
    roomHandlerText,
    socketHandlerText,
    zoomWebhookText,
    zoomRoomStateMigrationText,
  } = await fixtures();
  assert.deepEqual(
    validateRLSSchema(
      migrationText,
      tableRLSTestText,
      handlerRLSTestText,
      portHandlerRLSTestText,
      aiAuditRLSTestText,
      authSessionRLSTestText,
      authHandlerText,
      platformMainText,
      roomHandlerText,
      socketHandlerText,
      zoomWebhookText,
      zoomRoomStateMigrationText,
    ),
    { tenantScopedTableCount: 9 },
  );
});

test('validateRLSSchema rejects a weakened Zoom mapping RLS policy', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, authHandlerText, platformMainText, roomHandlerText, socketHandlerText, zoomWebhookText } = await fixtures();
  const broken = migrationText.replace("app.webhook_lookup_verified", "app.webhook_lookup_disabled");
  assert.notEqual(broken, migrationText, 'test fixture must remove the verified Zoom mapping policy');
  assert.throws(
    () => validateRLSSchema(broken, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, authHandlerText, platformMainText, roomHandlerText, socketHandlerText, zoomWebhookText),
    /verified Zoom mapping RLS policy/,
  );
});

test('discoverTenantScopedTables derives tenant coverage from migration tables', async () => {
  const { migrationText } = await fixtures();
  assert.deepEqual(discoverTenantScopedTables(migrationText), [
    'organizations',
    'users',
    'scripture_texts',
    'refresh_tokens',
    'journal_entries',
    'live_rooms',
    'room_participants',
    'ai_request_logs',
    'citation_trails',
  ]);
});

test('validateRLSSchema rejects new tenant tables not added to RLS coverage', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = migrationText.replace(
    'CREATE INDEX idx_ai_request_logs_org_created ON ai_request_logs(organization_id, created_at DESC);',
    `CREATE INDEX idx_ai_request_logs_org_created ON ai_request_logs(organization_id, created_at DESC);

CREATE TABLE prayer_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    content TEXT NOT NULL
);`,
  );
  assert.notEqual(broken, migrationText, 'test fixture must add a tenant-scoped table');
  assert.throws(
    () => validateRLSSchema(broken, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText),
    /tenantScopedTables must match every migration table carrying tenant data/,
  );
});

test('validateRLSSchema rejects tenant tables without forced RLS', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = migrationText.replace('ALTER TABLE journal_entries FORCE ROW LEVEL SECURITY;', '');
  assert.notEqual(broken, migrationText, 'test fixture must remove journal_entries forced RLS');
  assert.throws(
    () => validateRLSSchema(broken, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText),
    /journal_entries must force row-level security/,
  );
});

test('validateRLSSchema rejects tenant policies without app.current_org_id checks', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = migrationText.replace(
    "CREATE POLICY refresh_token_isolation_policy ON refresh_tokens\n    USING (organization_id = current_setting('app.current_org_id', true)::UUID)\n    WITH CHECK (organization_id = current_setting('app.current_org_id', true)::UUID);",
    'CREATE POLICY refresh_token_isolation_policy ON refresh_tokens\n    USING (true)\n    WITH CHECK (true);',
  );
  assert.notEqual(broken, migrationText, 'test fixture must remove refresh_tokens tenant policy checks');
  assert.throws(
    () => validateRLSSchema(broken, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText),
    /refresh_tokens must define an app.current_org_id USING policy/,
  );
});

test('validateRLSSchema rejects missing handler-level RLS proof markers', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = handlerRLSTestText.replace('TestTenantScopedRoomActiveHandlerEnforcesRLS', 'TestRoomActiveHandler');
  assert.notEqual(broken, handlerRLSTestText, 'test fixture must remove room handler proof marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, broken, portHandlerRLSTestText, aiAuditRLSTestText),
    /TestTenantScopedRoomActiveHandlerEnforcesRLS/,
  );
});

test('validateRLSSchema rejects weakened handler-level journal assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = handlerRLSTestText.replace('cross-tenant journal read status', 'cross tenant journal status');
  assert.notEqual(broken, handlerRLSTestText, 'test fixture must remove cross-tenant journal assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, broken, portHandlerRLSTestText, aiAuditRLSTestText),
    /cross-tenant journal read status/,
  );
});

test('validateRLSSchema rejects weakened room-state handler RLS assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = handlerRLSTestText.replace('cross-tenant room state reached polling store %d times, want 0', 'cross-tenant room state polling store checked');
  assert.notEqual(broken, handlerRLSTestText, 'test fixture must remove room-state store guard marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, broken, portHandlerRLSTestText, aiAuditRLSTestText),
    /cross-tenant room state reached polling store %d times, want 0/,
  );
});

test('validateRLSSchema rejects missing ports tenant-isolation proof markers', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = portHandlerRLSTestText.replace('TestSocketStreamIsTenantScoped', 'TestSocketStream');
  assert.notEqual(broken, portHandlerRLSTestText, 'test fixture must remove socket tenant proof marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, broken, aiAuditRLSTestText),
    /TestSocketStreamIsTenantScoped/,
  );
});

test('validateRLSSchema rejects weakened ports tenant-isolation assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = portHandlerRLSTestText.replace('tenant B can see room from another tenant', 'tenant B room visibility');
  assert.notEqual(broken, portHandlerRLSTestText, 'test fixture must remove cross-tenant room assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, broken, aiAuditRLSTestText),
    /tenant B can see room from another tenant/,
  );
});

test('validateRLSSchema rejects weakened mismatched tenant room-create assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = portHandlerRLSTestText.replace('mismatched tenant/user room create persisted %d participants, want 0', 'mismatched tenant/user participant count');
  assert.notEqual(broken, portHandlerRLSTestText, 'test fixture must remove mismatched tenant/user room participant assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, broken, aiAuditRLSTestText),
    /mismatched tenant\/user room create persisted %d participants, want 0/,
  );
});

test('validateRLSSchema rejects missing AI audit tenant-isolation proof markers', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = aiAuditRLSTestText.replace('TestGenerateCurriculumHandlerPersistsAuditRowsWithTenantRLS', 'TestGenerateCurriculumHandlerPersistsAuditRows');
  assert.notEqual(broken, aiAuditRLSTestText, 'test fixture must remove AI audit handler proof marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, broken),
    /TestGenerateCurriculumHandlerPersistsAuditRowsWithTenantRLS/,
  );
});

test('validateRLSSchema rejects weakened AI audit tenant assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = aiAuditRLSTestText.replace('handler AI audit counts logs=%d citations=%d, want 1/1', 'handler AI audit counts logs=%d citations=%d');
  assert.notEqual(broken, aiAuditRLSTestText, 'test fixture must remove same-tenant AI audit assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, broken),
    /handler AI audit counts logs=%d citations=%d, want 1\/1/,
  );
});

test('validateRLSSchema rejects missing auth refresh-token tenant assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, authHandlerText } = await fixtures();
  const broken = authSessionRLSTestText.replace('cross-tenant refresh status', 'cross tenant refresh status');
  assert.notEqual(broken, authSessionRLSTestText, 'test fixture must remove cross-tenant auth refresh assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, broken, authHandlerText),
    /cross-tenant refresh status/,
  );
});

test('validateRLSSchema rejects missing privileged MFA login assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, authHandlerText } = await fixtures();
  const broken = authSessionRLSTestText.replace('missing MFA login status', 'missing privileged login status');
  assert.notEqual(broken, authSessionRLSTestText, 'test fixture must remove privileged MFA login assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, broken, authHandlerText),
    /missing MFA login status/,
  );
});

test('validateRLSSchema rejects missing workspace switch tenant-match assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, authHandlerText } = await fixtures();
  const broken = authSessionRLSTestText.replace('workspace switch cross-tenant status', 'workspace switch forbidden status');
  assert.notEqual(broken, authSessionRLSTestText, 'test fixture must remove workspace switch cross-tenant assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, broken, authHandlerText),
    /workspace switch cross-tenant status/,
  );
});

test('validateRLSSchema rejects missing MFA enrollment and verification assertions', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, authHandlerText } = await fixtures();
  const broken = authSessionRLSTestText.replace('member mfa verify status', 'member mfa status');
  assert.notEqual(broken, authSessionRLSTestText, 'test fixture must remove member MFA authorization assertion marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, broken, authHandlerText),
    /member mfa verify status/,
  );
});

test('validateRLSSchema rejects missing auth refresh-token tenant context wiring', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, authHandlerText } = await fixtures();
  const broken = authHandlerText.replaceAll('auth.SetTenantContext', 'auth.SetSessionContext');
  assert.notEqual(broken, authHandlerText, 'test fixture must remove auth.SetTenantContext wiring marker');
  assert.throws(
    () => validateRLSSchema(migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText, authSessionRLSTestText, broken),
    /auth\.SetTenantContext/,
  );
});

test('validateProductionRoomMembershipWiring accepts production DB-backed route wiring', async () => {
  const { platformMainText, roomHandlerText, socketHandlerText } = await fixtures();
  assert.doesNotThrow(() => validateProductionRoomMembershipWiring(platformMainText, roomHandlerText, socketHandlerText));
});

test('validateProductionRoomMembershipWiring rejects production room membership overrides', async () => {
  const { platformMainText, roomHandlerText, socketHandlerText } = await fixtures();
  const broken = platformMainText.replace(
    /([\t ]*MeetingProvider:\s*"zoom",)/,
    '$1\n\t\tMembershipValidator: func(*http.Request, *auth.TokenClaims, string) bool { return true },',
  );
  assert.notEqual(broken, platformMainText, 'test fixture must add a production RoomHandler membership override');
  assert.throws(
    () => validateProductionRoomMembershipWiring(broken, roomHandlerText, socketHandlerText),
    /production RoomHandler must be constructed without a MembershipValidator override/,
  );
});

test('validateProductionRoomMembershipWiring rejects production socket membership overrides', async () => {
  const { platformMainText, roomHandlerText, socketHandlerText } = await fixtures();
  const broken = platformMainText.replace(
    /(\tsocketConn := &ports\.SocketConnection\{[\s\S]*?ConnectionLimiter: abuse\.NewDefaultRedisActiveConnectionLimiter\(redisClient\),\n)(\t\})/,
    '$1\tMembershipValidator: func(*http.Request, *auth.TokenClaims, string) bool { return true },\n$2',
  );
  assert.notEqual(broken, platformMainText, 'test fixture must add a production SocketConnection membership override');
  assert.throws(
    () => validateProductionRoomMembershipWiring(broken, roomHandlerText, socketHandlerText),
    /production SocketConnection must be constructed without a MembershipValidator override/,
  );
});

test('validateProductionRoomMembershipWiring rejects tenantless socket membership checks', async () => {
  const { platformMainText, roomHandlerText, socketHandlerText } = await fixtures();
  const broken = socketHandlerText.replace('WHERE organization_id = $1 AND room_id = $2 AND user_id = $3', 'WHERE room_id = $1 AND user_id = $2');
  assert.notEqual(broken, socketHandlerText, 'test fixture must weaken socket membership SQL');
  assert.throws(
    () => validateProductionRoomMembershipWiring(platformMainText, roomHandlerText, broken),
    /SocketConnection membership validation must use tenant-scoped Postgres\/RLS checks/,
  );
});

test('validateRLSSchema rejects missing table-level read/write RLS proof markers', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = tableRLSTestText.replaceAll('assertTenantScopedRowVisibility', 'assertTenantRows');
  assert.notEqual(broken, tableRLSTestText, 'test fixture must remove table visibility proof marker');
  assert.throws(
    () => validateRLSSchema(migrationText, broken, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText),
    /assertTenantScopedRowVisibility/,
  );
});

test('validateRLSSchema rejects missing table-level update/delete RLS proof markers', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = tableRLSTestText.replaceAll('requireRLSMutationHidden', 'requireRLSMutation');
  assert.notEqual(broken, tableRLSTestText, 'test fixture must remove table mutation proof marker');
  assert.throws(
    () => validateRLSSchema(migrationText, broken, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText),
    /requireRLSMutationHidden/,
  );
});

test('validateRLSSchema rejects missing same-tenant table mutation proof markers', async () => {
  const { migrationText, tableRLSTestText, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText } = await fixtures();
  const broken = tableRLSTestText.replaceAll('requireRLSMutationAffects', 'requireRLSMutation');
  assert.notEqual(broken, tableRLSTestText, 'test fixture must remove same-tenant mutation proof marker');
  assert.throws(
    () => validateRLSSchema(migrationText, broken, handlerRLSTestText, portHandlerRLSTestText, aiAuditRLSTestText),
    /requireRLSMutationAffects/,
  );
});
