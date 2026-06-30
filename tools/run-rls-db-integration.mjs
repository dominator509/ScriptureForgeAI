import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

const isWindows = process.platform === 'win32';
const defaultGoBin = isWindows ? '.\\.tools\\go\\bin\\go.exe' : './.tools/go/bin/go';

export const rlsDBTestPattern = 'Test(TenantRLSCoversAllTenantTables|TenantScopedJournalHandlersEnforceRLS|TenantScopedRoomActiveHandlerEnforcesRLS|JournalHandlersHonorTenantIsolation|RoomHandlersHonorTenantIsolation|SocketStreamIsTenantScoped|AIRequestLogPersistsCitationsAndHonorsTenantRLS|GenerateCurriculumHandlerPersistsAuditRowsWithTenantRLS|AuthRegisterLoginRefreshRotationAndLogout|PrivilegedLoginRequiresAndVerifiesMFA|WorkspaceSwitchRequiresAuthenticatedOrgMatch|MFAEnrollAndVerifyFlowForPrivilegedUsers)';

export const rlsDBRequiredTests = [
  'TenantRLSCoversAllTenantTables',
  'TenantScopedJournalHandlersEnforceRLS',
  'TenantScopedRoomActiveHandlerEnforcesRLS',
  'JournalHandlersHonorTenantIsolation',
  'RoomHandlersHonorTenantIsolation',
  'SocketStreamIsTenantScoped',
  'AIRequestLogPersistsCitationsAndHonorsTenantRLS',
  'GenerateCurriculumHandlerPersistsAuditRowsWithTenantRLS',
  'AuthRegisterLoginRefreshRotationAndLogout',
  'PrivilegedLoginRequiresAndVerifiesMFA',
  'WorkspaceSwitchRequiresAuthenticatedOrgMatch',
  'MFAEnrollAndVerifyFlowForPrivilegedUsers',
];

export const rlsDBSemanticProofMarkers = [
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
  'rls_same_tenant_reads_pass=true',
  'rls_cross_tenant_reads_denied=true',
  'rls_cross_tenant_writes_denied=true',
  'rls_cross_tenant_updates_hidden=true',
  'rls_cross_tenant_deletes_hidden=true',
  'journal_handler_rls=true',
  'journal_plaintext_rejected=true',
  'room_active_handler_rls=true',
  'room_create_tenant_override_denied=true',
  'websocket_tenant_scoping=true',
  'ai_audit_rls=true',
  'generated_curriculum_audit_rls=true',
  'auth_refresh_session_rls=true',
  'auth_mfa_rls=true',
  'workspace_switch_tenant_match=true',
  'privileged_mfa_enrollment_rls=true',
];

export const rlsDBProofMarkers = [
  ...rlsDBRequiredTests,
  ...rlsDBSemanticProofMarkers,
];

export function validateRLSDBGoTestOutput(output) {
  const text = String(output ?? '');
  for (const testName of rlsDBRequiredTests) {
    const passPattern = new RegExp(`--- PASS: Test${testName}\\b`);
    assertTestOutput(passPattern.test(text), `rls-db-integration Go test output must include PASS for Test${testName}`);
    const skipPattern = new RegExp(`--- SKIP: Test${testName}\\b`);
    assertTestOutput(!skipPattern.test(text), `rls-db-integration Go test output must not skip Test${testName}`);
  }
}

export function validateDatabaseURL(env = process.env) {
  const databaseURL = env.DATABASE_URL ?? '';
  if (!databaseURL || databaseURL.includes('${')) {
    throw new Error('DATABASE_URL is required for rls-db-integration; set it to a migrated Postgres/pgvector database before collecting local readiness evidence');
  }
}

export function buildRLSDBIntegrationCommand({ goBin = defaultGoBin } = {}) {
  return [
    goBin,
    'test',
    './tests/integration',
    './internal/ports',
    '-run',
    rlsDBTestPattern,
    '-count=1',
    '-timeout=90s',
    '-v',
  ];
}

export function buildRLSDBIntegrationEnv(env = process.env, workspaceRoot = process.cwd()) {
  return {
    ...env,
    GOCACHE: env.GOCACHE || resolve(workspaceRoot, '.gocache'),
    REQUIRE_DATABASE_URL: 'true',
  };
}

export function runRLSDBIntegration({ env = process.env, workspaceRoot = process.cwd(), goBin = defaultGoBin } = {}) {
  validateDatabaseURL(env);
  const [command, ...args] = buildRLSDBIntegrationCommand({ goBin });
  return new Promise((resolveRun) => {
    const child = spawn(command, args, {
      cwd: workspaceRoot,
      env: buildRLSDBIntegrationEnv(env, workspaceRoot),
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stdout.write(text);
    });
    child.stderr?.on('data', (chunk) => {
      const text = chunk.toString();
      stderr += text;
      process.stderr.write(text);
    });
    child.on('error', (error) => {
      console.error(error.message);
      resolveRun(1);
    });
    child.on('close', (code) => {
      const exitCode = code ?? 1;
      if (exitCode === 0) {
        try {
          validateRLSDBGoTestOutput(`${stdout}\n${stderr}`);
          console.log(`rls-db-integration proof: ${rlsDBProofMarkers.join(', ')}`);
        } catch (error) {
          console.error(error.message);
          resolveRun(1);
          return;
        }
      }
      resolveRun(exitCode);
    });
  });
}

function assertTestOutput(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function main() {
  try {
    const exitCode = await runRLSDBIntegration();
    process.exit(exitCode);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('run-rls-db-integration.mjs')) {
  main();
}
