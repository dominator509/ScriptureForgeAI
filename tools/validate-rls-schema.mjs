import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export const tenantScopedTables = [
  'organizations',
  'users',
  'scripture_texts',
  'refresh_tokens',
  'journal_entries',
  'live_rooms',
  'room_participants',
  'ai_request_logs',
  'citation_trails',
];

export function validateRLSSchema(
  migrationText,
  tableRLSTestText,
  handlerRLSTestText,
  portHandlerRLSTestText = '',
  aiAuditRLSTestText = '',
  authSessionRLSTestText = '',
  authHandlerText = '',
  platformMainText = '',
  roomHandlerText = '',
  socketHandlerText = '',
) {
  assert.deepEqual(
    discoverTenantScopedTables(migrationText),
    tenantScopedTables,
    'tenantScopedTables must match every migration table carrying tenant data',
  );

  assert.ok(
    migrationText.includes("current_setting('app.current_org_id', true)::UUID"),
    'RLS policies must use app.current_org_id as the tenant context source',
  );

  for (const table of tenantScopedTables) {
    assert.ok(
      migrationText.includes(`ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`),
      `${table} must enable row-level security`,
    );
    assert.ok(
      migrationText.includes(`ALTER TABLE ${table} FORCE ROW LEVEL SECURITY;`),
      `${table} must force row-level security`,
    );
    assert.ok(
      /USING\s*\([\s\S]*?app\.current_org_id[\s\S]*?\)/m.test(policyForTable(migrationText, table)),
      `${table} must define an app.current_org_id USING policy`,
    );
    assert.ok(
      /WITH CHECK\s*\([\s\S]*?app\.current_org_id[\s\S]*?\);/m.test(policyForTable(migrationText, table)),
      `${table} must define an app.current_org_id WITH CHECK policy`,
    );
    assert.ok(
      tableRLSTestText.includes(`"${table}"`) || tableRLSTestText.includes(table),
      `table RLS integration test must mention ${table}`,
    );
  }

  for (const requiredHandlerProof of [
    'TestTenantScopedJournalHandlersEnforceRLS',
    'TestTenantScopedRoomActiveHandlerEnforcesRLS',
    'TestTenantScopedRoomStateHandlerEnforcesRLS',
    'plaintext journal payload persisted %d rows, want 0',
    'plaintext ciphertext journal payload status',
    'journal table contains plaintext leak markers',
    'same-tenant journal create status',
    'same-tenant journal list',
    'same-tenant different-user read status',
    'cross-tenant journal read status',
    'mismatched tenant/user',
    'tenant A rooms',
    'tenant B rooms',
    'mismatched tenant/user rooms',
    'cross-tenant room state status',
    'cross-tenant room state reached polling store %d times, want 0',
    'same-tenant room state status',
    'same-tenant room state polling store calls = %d, want 1',
    'cross-tenant',
  ]) {
    assert.ok(
      handlerRLSTestText.includes(requiredHandlerProof),
      `handler-level RLS integration proof missing ${requiredHandlerProof}`,
    );
  }
  for (const requiredPortHandlerProof of [
    'TestJournalHandlersHonorTenantIsolation',
    'TestRoomHandlersHonorTenantIsolation',
    'TestSocketStreamIsTenantScoped',
    'assertCrossTenantWriteBlocked',
    'tenant B direct read cross-tenant status',
    'tenant B can read entries from another tenant',
    'tenant A list expected one matching entry',
    'tenant override room create',
    'mismatched tenant/user room create unexpectedly succeeded',
    'mismatched tenant/user room create persisted %d rooms, want 0',
    'mismatched tenant/user room create persisted %d participants, want 0',
    'tenant B can see room from another tenant',
    'tenant A active rooms expected one matching room',
    'tenant B room state status',
    'tenant A room state status',
    'cross-tenant socket dial expected to fail',
    'tenant B event append count = %d, want 0',
  ]) {
    assert.ok(
      portHandlerRLSTestText.includes(requiredPortHandlerProof),
      `ports tenant isolation proof missing ${requiredPortHandlerProof}`,
    );
  }
  for (const requiredAIAuditProof of [
    'TestGenerateCurriculumHandlerPersistsAuditRowsWithTenantRLS',
    'TestAIRequestLogPersistsCitationsAndHonorsTenantRLS',
    'ai_request_logs',
    'citation_trails',
    'cross-tenant handler AI audit visibility',
    'cross-tenant AI audit visibility',
    'AI audit counts success=%d failure=%d citations=%d, want 1/1/2',
    'handler AI audit counts logs=%d citations=%d, want 1/1',
    'want 0/0',
    'auth.SetTenantContext',
  ]) {
    assert.ok(
      aiAuditRLSTestText.includes(requiredAIAuditProof),
      `AI audit tenant isolation proof missing ${requiredAIAuditProof}`,
    );
  }
  if (authSessionRLSTestText) {
    for (const requiredAuthSessionProof of [
      'TestAuthRegisterLoginRefreshRotationAndLogout',
      'refresh_tokens',
      'expired refresh token status',
      'rotated refresh token',
      'old refresh token status',
      'cross-tenant refresh status',
      'logout status',
      'revoked refresh token status',
      'TestPrivilegedLoginRequiresAndVerifiesMFA',
      'missing MFA login status',
      'verified MFA login status',
      'verified MFA claims',
      'privileged auth dependency metrics missing',
      'TestWorkspaceSwitchRequiresAuthenticatedOrgMatch',
      'workspace switch status',
      'workspace switch cross-tenant status',
      'TestMFAEnrollAndVerifyFlowForPrivilegedUsers',
      'mfa enroll status',
      'mfa verify wrong-code status',
      'mfa verify status',
      'member mfa verify status',
      'MFA dependency metrics missing',
    ]) {
      assert.ok(
        authSessionRLSTestText.includes(requiredAuthSessionProof),
        `auth refresh-token tenant isolation proof missing ${requiredAuthSessionProof}`,
      );
    }
  }
  if (authHandlerText) {
    for (const requiredAuthHandlerProof of [
      'func (h *AuthHandler) RefreshHandler',
      'func (h *AuthHandler) LogoutHandler',
      'auth.SetTenantContext',
      'refresh_tokens',
    ]) {
      assert.ok(
        authHandlerText.includes(requiredAuthHandlerProof),
        `auth refresh-token handler tenant context proof missing ${requiredAuthHandlerProof}`,
      );
    }
  }
  if (platformMainText || roomHandlerText || socketHandlerText) {
    validateProductionRoomMembershipWiring(platformMainText, roomHandlerText, socketHandlerText);
  }
  for (const requiredTableProof of [
    'assertTenantScopedRowVisibility',
    'assertSameTenantUpdatesAndDeletesPassAllTables',
    'same-tenant read visible',
    'same-tenant update visible',
    'same-tenant delete visible',
    'cross-tenant read hidden',
    'requireRLSWriteDenied',
    'requireRLSMutationAffects',
    'requireRLSMutationHidden',
    'cross-tenant update hidden',
    'cross-tenant delete hidden',
  ]) {
    assert.ok(
      tableRLSTestText.includes(requiredTableProof),
      `table RLS integration proof missing ${requiredTableProof}`,
    );
  }

  return { tenantScopedTableCount: tenantScopedTables.length };
}

export function validateProductionRoomMembershipWiring(platformMainText, roomHandlerText, socketHandlerText) {
	const roomHandlerConstruction = platformMainText.match(/roomHandler\s*:=\s*&ports\.RoomHandler\s*{([\s\S]*?)}/m);
	assert.ok(roomHandlerConstruction, 'production RoomHandler must be constructed without a MembershipValidator override');
	assert.doesNotMatch(
		roomHandlerConstruction[1],
		/\bMembershipValidator\s*:/m,
		'production RoomHandler must be constructed without a MembershipValidator override',
	);
	const socketConstruction = platformMainText.match(/socketConn\s*:=\s*&ports\.SocketConnection\s*{([\s\S]*?)}/m);
	assert.ok(socketConstruction, 'production SocketConnection must be constructed without a MembershipValidator override');
	assert.doesNotMatch(
		socketConstruction[1],
		/\bMembershipValidator\s*:/m,
		'production SocketConnection must be constructed without a MembershipValidator override',
	);
  assert.ok(
    roomHandlerText.includes('func (h *RoomHandler) validateRoomMembership') &&
      roomHandlerText.includes('auth.SetTenantContext') &&
      roomHandlerText.includes('FROM room_participants') &&
      roomHandlerText.includes('WHERE organization_id = $1 AND room_id = $2 AND user_id = $3'),
    'RoomHandler membership validation must use tenant-scoped Postgres/RLS checks',
  );
  assert.ok(
    socketHandlerText.includes('func (s *SocketConnection) validateRoomMembership') &&
      socketHandlerText.includes('auth.SetTenantContext') &&
      socketHandlerText.includes('FROM room_participants') &&
      socketHandlerText.includes('WHERE organization_id = $1 AND room_id = $2 AND user_id = $3'),
    'SocketConnection membership validation must use tenant-scoped Postgres/RLS checks',
  );
}

export function discoverTenantScopedTables(migrationText) {
  return [...migrationText.matchAll(/CREATE TABLE\s+(\w+)\s*\(([\s\S]*?)\);/gm)]
    .filter(([, table, body]) => table === 'organizations' || /\borganization_id\b/.test(body))
    .map(([, table]) => table);
}

function policyForTable(migrationText, table) {
  const match = migrationText.match(new RegExp(`CREATE POLICY\\s+\\w+\\s+ON\\s+${table}\\s+[\\s\\S]*?;`, 'm'));
  assert.ok(match, `${table} must define an RLS policy`);
  return match[0];
}

async function main() {
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
  ]);
  const result = validateRLSSchema(
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
  );
  console.log(`RLS schema invariants validated across ${result.tenantScopedTableCount} tenant-scoped tables`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-rls-schema.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
