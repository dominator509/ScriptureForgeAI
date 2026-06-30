import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { clientCommandProofMarkers } from './run-client-command.mjs';
import { goTestProofMarkers, goVetProofMarkers } from './run-go-core-gate.mjs';
import { goProbeProofMarkers } from './run-go-probe-tests.mjs';
import { ciEvidenceGateProofMarkers } from './validate-ci-evidence-gates.mjs';
import { ciWorkflowProofMarkers } from './validate-ci-workflow.mjs';
import { dependencyRiskProofMarkers } from './validate-dependency-risk.mjs';
import { deploymentSkeletonProofMarkers } from './validate-deployment-skeleton.mjs';
import { journalCryptoProofMarkers } from './verify-journal-crypto.mjs';
import { observabilityProofMarkers } from './validate-observability.mjs';
import { gateDefinitions } from './run-local-gates.mjs';
import { npmAuditProofMarkers } from './run-npm-audit.mjs';
import { terraformFmtProofMarkers, terraformValidateProofMarkers } from './run-terraform-command.mjs';
import { terraformInitProofMarkers } from './run-terraform-init.mjs';
import { rlsDBProofMarkers } from './run-rls-db-integration.mjs';
import { rustCargoProofMarkers } from './run-rust-cargo-gate.mjs';
import { rustProtobufProofMarkers } from './verify-rust-protobuf.mjs';
import { securityArtifactsProofMarkers } from './validate-security-artifacts.mjs';
import { secretHygieneProofMarkers } from './validate-secret-hygiene.mjs';
import { stagingEvidenceContractProofMarkers } from './sync-staging-evidence-contract.mjs';
import { stagingEvidenceProofMarkers } from './validate-staging-evidence.mjs';
import { obsidianReadinessProofMarkers } from './sync-obsidian-readiness.mjs';
import { stagingEvidenceGapReportProofMarkers } from './report-staging-evidence-gaps.mjs';
import { projectPathProofMarkers, strictStagingPathProofMarkers } from './verify-project-path.mjs';

export { rustCargoProofMarkers } from './run-rust-cargo-gate.mjs';

const requiredGateIds = new Set(gateDefinitions.map((gate) => gate.id));
const expectedGateCommands = new Map(gateDefinitions.map((gate) => [gate.id, commandDisplay(gate)]));
export const webSmokeProofMarkers = [
  'web_api_auth_routes=true',
  'web_api_encrypted_journal=true',
  'web_api_rooms_ws=true',
  'web_runtime_strict_endpoint_guard=true',
  'web_crypto_aes_gcm=true',
  'web_crypto_associated_data=true',
  'web_crypto_pbkdf2_600000=true',
  'web_crypto_key_disposal=true',
];
export const mobileSmokeProofMarkers = [
  'mobile_api_auth_mfa=true',
  'mobile_api_encrypted_journal=true',
  'mobile_api_rooms_ws=true',
  'mobile_runtime_native_required_guard=true',
  'mobile_crypto_aes_gcm=true',
  'mobile_crypto_associated_data=true',
  'mobile_crypto_native_required_fail_closed=true',
  'mobile_crypto_self_test_markers=true',
];
export const webTypecheckProofMarkers = [
  ...clientCommandProofMarkers,
  'web_typescript_no_emit=true',
  'web_runtime_types=true',
];
export const webBuildProofMarkers = [
  ...clientCommandProofMarkers,
  'next_build=true',
  'web_production_bundle=true',
];
export const mobileBuildCheckProofMarkers = [
  ...clientCommandProofMarkers,
  'mobile_typecheck=true',
  'mobile_smoke=true',
  'mobile_crypto_verification=true',
];

export function validateLocalGateReport(report, {
  allowDryRun = false,
  requireAllGates = true,
  allowDirty = false,
  allowUnsynced = false,
  today = new Date().toISOString().slice(0, 10),
} = {}) {
  assert.equal(report.schema_version, 1, 'local gate report schema_version must be 1');
  assert.match(report.git_head, /^[a-fA-F0-9]{40}$/, 'git_head must be a full 40-character commit SHA');
  assert.equal(typeof report.git_branch, 'string', 'git_branch is required');
  assert.equal(typeof report.git_upstream, 'string', 'git_upstream is required');
  assert.equal(typeof report.git_ahead, 'number', 'git_ahead is required');
  assert.equal(typeof report.git_behind, 'number', 'git_behind is required');
  assert.equal(typeof report.git_status_clean, 'boolean', 'git_status_clean is required');
  assert.equal(typeof report.git_status_short, 'string', 'git_status_short is required');
  assert.match(report.observed_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 'observed_at must be ISO UTC without milliseconds');
  assert.match(today, /^\d{4}-\d{2}-\d{2}$/, 'today must be YYYY-MM-DD');
  assert.ok(
    report.observed_at.slice(0, 10) <= today,
    'local gate report observed_at must not be after validation date',
  );
  assert.equal(typeof report.threshold_pass, 'boolean', 'threshold_pass is required');
  assert.equal(typeof report.dry_run, 'boolean', 'dry_run is required');
  assert.equal(typeof report.gates_total, 'number', 'gates_total is required');
  assert.equal(typeof report.gates_run, 'number', 'gates_run is required');
  assert.equal(typeof report.gates_failed, 'number', 'gates_failed is required');
  assert.ok(Array.isArray(report.results), 'results must be an array');

  if (!allowDryRun) {
    assert.equal(report.dry_run, false, 'dry-run reports cannot satisfy local gate evidence');
  }
  if (!allowDirty) {
    assert.equal(report.git_status_clean, true, `local gate report requires a clean worktree; git_status_short=${JSON.stringify(report.git_status_short)}`);
  }
  if (!allowUnsynced) {
    assert.ok(report.git_upstream.length > 0, 'local gate report requires an upstream branch');
    assert.equal(report.git_ahead, 0, 'local gate report branch must not be ahead of upstream');
    assert.equal(report.git_behind, 0, 'local gate report branch must not be behind upstream');
  }
  assert.equal(report.threshold_pass, true, 'local gate report threshold_pass must be true');
  assert.equal(report.gates_failed, 0, 'local gate report must have zero failed gates');
  assert.equal(report.gates_run, report.results.length, 'gates_run must match results length');
  assert.equal(report.gates_total, report.results.length, 'gates_total must match results length');

  const seen = new Set();
  for (const result of report.results) {
    assert.equal(typeof result.id, 'string', 'gate result id is required');
    assert.ok(!seen.has(result.id), `duplicate local gate result ${result.id}`);
    seen.add(result.id);
    assert.ok(requiredGateIds.has(result.id), `unknown local gate result ${result.id}`);
    assert.equal(typeof result.command, 'string', `${result.id} command is required`);
    assert.equal(
      result.command,
      expectedGateCommands.get(result.id),
      `${result.id} command must match the canonical local gate command`,
    );
    assert.equal(typeof result.cwd, 'string', `${result.id} cwd is required`);
    assert.equal(typeof result.skipped, 'boolean', `${result.id} skipped is required`);
    if (!allowDryRun) {
      assert.equal(result.skipped, false, `${result.id} must not be skipped in local gate evidence`);
    }
    assert.equal(result.exit_code, 0, `${result.id} exit_code must be 0`);
    assert.equal(typeof result.duration_ms, 'number', `${result.id} duration_ms is required`);
    assert.ok(result.duration_ms >= 0, `${result.id} duration_ms must be non-negative`);
    if (result.id === 'project-path-readiness') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /ScriptureForgeAI PATH readiness/, 'project-path-readiness output must include the PATH readiness summary');
      assert.match(output, /mode: local/, 'project-path-readiness output must run in local mode');
      assert.match(output, /path readiness proof:/, 'project-path-readiness output must include PATH proof markers');
      for (const marker of projectPathProofMarkers) {
        assert.ok(output.includes(marker), `project-path-readiness output must include ${marker}`);
      }
    }
    if (result.id === 'strict-staging-path-readiness') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /--strict-staging/, 'strict-staging-path-readiness command must require strict staging mode');
      assert.match(output, /ScriptureForgeAI PATH readiness/, 'strict-staging-path-readiness output must include the PATH readiness summary');
      assert.match(output, /mode: staging-evidence/, 'strict-staging-path-readiness output must run in staging-evidence mode');
      assert.match(output, /path readiness proof:/, 'strict-staging-path-readiness output must include strict PATH proof markers');
      for (const marker of strictStagingPathProofMarkers) {
        assert.ok(output.includes(marker), `strict-staging-path-readiness output must include ${marker}`);
      }
    }
    if (result.id === 'go-test') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /tools[\\/]run-go-core-gate\.mjs --mode test/, 'go-test command must use tools/run-go-core-gate.mjs in test mode');
      assert.match(output, /go-test-gate validated:/, 'go-test output must include the Go test proof summary');
      for (const marker of goTestProofMarkers) {
        assert.ok(output.includes(marker), `go-test output must include ${marker}`);
      }
    }
    if (result.id === 'go-vet') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /tools[\\/]run-go-core-gate\.mjs --mode vet/, 'go-vet command must use tools/run-go-core-gate.mjs in vet mode');
      assert.match(output, /go-vet-gate validated:/, 'go-vet output must include the Go vet proof summary');
      for (const marker of goVetProofMarkers) {
        assert.ok(output.includes(marker), `go-vet output must include ${marker}`);
      }
    }
    if (result.id === 'rls-db-integration') {
      assert.match(result.command, /REQUIRE_DATABASE_URL=true/, 'rls-db-integration command must force REQUIRE_DATABASE_URL=true');
      assert.match(
        result.command,
        /tools[\\/]run-rls-db-integration(?:-docker)?\.mjs/,
        'rls-db-integration command must use tools/run-rls-db-integration.mjs or tools/run-rls-db-integration-docker.mjs',
      );
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /rls-db-integration proof:/, 'rls-db-integration output must include the DB-backed proof summary');
      for (const marker of rlsDBProofMarkers) {
        assert.match(output, new RegExp(marker), `rls-db-integration output must include ${marker}`);
      }
    }
    if (result.id === 'evidence-probes') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /tools[\\/]run-go-probe-tests\.mjs/, 'evidence-probes command must use tools/run-go-probe-tests.mjs');
      assert.match(output, /production evidence probe tests validated:/, 'evidence-probes output must include the production evidence probe proof summary');
      for (const marker of goProbeProofMarkers) {
        assert.ok(output.includes(marker), `evidence-probes output must include ${marker}`);
      }
    }
    if (result.id === 'web-audit' || result.id === 'mobile-audit') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /npm audit gate validated:/, `${result.id} output must include the npm audit proof summary`);
      for (const marker of npmAuditProofMarkers) {
        assert.ok(output.includes(marker), `${result.id} output must include ${marker}`);
      }
      if (result.id === 'web-audit') {
        assert.match(result.command, /--level moderate/, 'web-audit command must enforce moderate audit level');
      }
      if (result.id === 'mobile-audit') {
        assert.match(result.command, /--level high/, 'mobile-audit command must enforce high audit level');
      }
    }
    if (result.id === 'web-smoke') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /web api smoke proof:/, 'web-smoke output must include the web API smoke proof summary');
      assert.match(output, /web crypto smoke proof:/, 'web-smoke output must include the web crypto smoke proof summary');
      for (const marker of webSmokeProofMarkers) {
        assert.ok(output.includes(marker), `web-smoke output must include ${marker}`);
      }
    }
    if (result.id === 'web-typecheck') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /web-typecheck-gate validated:/, 'web-typecheck output must include the web typecheck proof summary');
      for (const marker of webTypecheckProofMarkers) {
        assert.ok(output.includes(marker), `web-typecheck output must include ${marker}`);
      }
    }
    if (result.id === 'web-build') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /web-build-gate validated:/, 'web-build output must include the web build proof summary');
      for (const marker of webBuildProofMarkers) {
        assert.ok(output.includes(marker), `web-build output must include ${marker}`);
      }
    }
    if (result.id === 'mobile-smoke') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /mobile api smoke proof:/, 'mobile-smoke output must include the mobile API smoke proof summary');
      assert.match(output, /mobile crypto smoke proof:/, 'mobile-smoke output must include the mobile crypto smoke proof summary');
      for (const marker of mobileSmokeProofMarkers) {
        assert.ok(output.includes(marker), `mobile-smoke output must include ${marker}`);
      }
    }
    if (result.id === 'mobile-build-check') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /mobile-build-check-gate validated:/, 'mobile-build-check output must include the mobile build-check proof summary');
      for (const marker of mobileBuildCheckProofMarkers) {
        assert.ok(output.includes(marker), `mobile-build-check output must include ${marker}`);
      }
    }
    if (result.id === 'rust-protobuf-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /Rust protobuf tooling verified:/, 'rust-protobuf-validation output must include the verifier proof summary');
      for (const marker of rustProtobufProofMarkers) {
        assert.match(output, new RegExp(marker), `rust-protobuf-validation output must include ${marker}`);
      }
    }
    if (result.id === 'rust-cargo-test') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /tools[\\/]run-rust-cargo-gate\.mjs --bin/, 'rust-cargo-test command must use the Rust cargo proof wrapper');
      for (const marker of rustCargoProofMarkers) {
        assert.match(output, new RegExp(marker), `rust-cargo-test output must include ${marker}`);
      }
    }
    if (result.id === 'terraform-fmt') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /tools[\\/]run-terraform-command\.mjs --mode fmt/, 'terraform-fmt command must use tools/run-terraform-command.mjs in fmt mode');
      assert.match(output, /terraform-fmt-gate validated:/, 'terraform-fmt output must include the Terraform fmt proof summary');
      for (const marker of terraformFmtProofMarkers) {
        assert.ok(output.includes(marker), `terraform-fmt output must include ${marker}`);
      }
    }
    if (result.id === 'terraform-init-validate') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /-backend=false/, 'terraform-init-validate command must keep local backend disabled');
      assert.match(output, /terraform init gate validated:/, 'terraform-init-validate output must include the Terraform init proof summary');
      for (const marker of terraformInitProofMarkers) {
        assert.ok(output.includes(marker), `terraform-init-validate output must include ${marker}`);
      }
    }
    if (result.id === 'terraform-validate') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /tools[\\/]run-terraform-command\.mjs --mode validate/, 'terraform-validate command must use tools/run-terraform-command.mjs in validate mode');
      assert.match(output, /terraform-validate-gate validated:/, 'terraform-validate output must include the Terraform validate proof summary');
      for (const marker of terraformValidateProofMarkers) {
        assert.ok(output.includes(marker), `terraform-validate output must include ${marker}`);
      }
    }
    if (result.id === 'deployment-skeleton-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /deployment skeleton and runtime config invariants validated:/, 'deployment-skeleton-validation output must include the deployment proof summary');
      for (const marker of deploymentSkeletonProofMarkers) {
        assert.ok(output.includes(marker), `deployment-skeleton-validation output must include ${marker}`);
      }
    }
    if (result.id === 'observability-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /observability artifacts validated:/, 'observability-validation output must include the observability proof summary');
      for (const marker of observabilityProofMarkers) {
        assert.ok(output.includes(marker), `observability-validation output must include ${marker}`);
      }
    }
    if (result.id === 'journal-crypto-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /journal crypto verification passed:/, 'journal-crypto-validation output must include the journal crypto proof summary');
      for (const marker of journalCryptoProofMarkers) {
        assert.ok(output.includes(marker), `journal-crypto-validation output must include ${marker}`);
      }
    }
    if (result.id === 'security-artifacts-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /security artifacts validated:/, 'security-artifacts-validation output must include the security artifacts proof summary');
      for (const marker of securityArtifactsProofMarkers) {
        assert.ok(output.includes(marker), `security-artifacts-validation output must include ${marker}`);
      }
    }
    if (result.id === 'dependency-risk-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /dependency risk validated:/, 'dependency-risk-validation output must include the dependency risk proof summary');
      for (const marker of dependencyRiskProofMarkers) {
        assert.ok(output.includes(marker), `dependency-risk-validation output must include ${marker}`);
      }
    }
    if (result.id === 'secret-hygiene-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /secret hygiene validated across \d+ text files:/, 'secret-hygiene-validation output must include the secret hygiene proof summary');
      for (const marker of secretHygieneProofMarkers) {
        assert.ok(output.includes(marker), `secret-hygiene-validation output must include ${marker}`);
      }
    }
    if (result.id === 'ci-workflow-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /CI workflow validated: .* \(\d+ required markers\):/, 'ci-workflow-validation output must include the CI workflow proof summary');
      for (const marker of ciWorkflowProofMarkers) {
        assert.ok(output.includes(marker), `ci-workflow-validation output must include ${marker}`);
      }
    }
    if (result.id === 'ci-evidence-gate-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /CI evidence gate markers validated across \d+ required entries and \d+ proof markers:/, 'ci-evidence-gate-validation output must include the CI evidence gate proof summary with required-entry and proof-marker counts');
      for (const marker of ciEvidenceGateProofMarkers) {
        assert.ok(output.includes(marker), `ci-evidence-gate-validation output must include ${marker}`);
      }
    }
    if (result.id === 'staging-evidence-contract-check') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /Staging evidence contract is in sync: .*:/, 'staging-evidence-contract-check output must include the staging evidence contract proof summary');
      for (const marker of stagingEvidenceContractProofMarkers) {
        assert.ok(output.includes(marker), `staging-evidence-contract-check output must include ${marker}`);
      }
    }
    if (result.id === 'staging-evidence-validation') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /staging evidence manifest validated(?: in strict release mode)?: .* \(\d+ items\):/, 'staging-evidence-validation output must include the staging evidence proof summary');
      for (const marker of stagingEvidenceProofMarkers) {
        assert.ok(output.includes(marker), `staging-evidence-validation output must include ${marker}`);
      }
    }
    if (result.id === 'staging-evidence-gap-report') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(result.command, /--allow-blockers/, 'staging-evidence-gap-report command must use --allow-blockers for local blocker rendering evidence');
      assert.match(output, /gap report proof footer: .*strict_release_ready=no/, 'staging-evidence-gap-report output must include the not-ready proof footer');
      const footerBlockingItems = output.match(/gap report proof footer: .*blocking_items=(\d+)/);
      assert.ok(footerBlockingItems, 'staging-evidence-gap-report output must include the blocking item count proof footer');
      const footerBlockingItemIDs = output.match(/gap report proof footer: .*blocking_item_ids=([^,\s]+)/);
      assert.ok(footerBlockingItemIDs, 'staging-evidence-gap-report output must include blocking item IDs in the proof footer');
      const footerStatusCounts = output.match(/gap report proof footer: .*counts=passed:\d+\|pending_external:\d+\|blocked:\d+\|failed:\d+\|accepted_risk:\d+\|non_manifest:\d+/);
      assert.ok(footerStatusCounts, 'staging-evidence-gap-report output must include status counts in the proof footer');
      assert.match(output, /- [A-Z0-9-]+ \[[a-z_]+\]/, 'staging-evidence-gap-report output must preserve rendered blocking items');
      assert.match(output, /^\s*required: .+/m, 'staging-evidence-gap-report output must preserve rendered required-evidence details');
      const footerIDCount = footerBlockingItemIDs[1] === 'none'
        ? 0
        : footerBlockingItemIDs[1].split('|').filter(Boolean).length;
      assert.equal(
        footerIDCount,
        Number(footerBlockingItems[1]),
        'staging-evidence-gap-report blocking item IDs must match the proof footer count',
      );
      for (const marker of stagingEvidenceGapReportProofMarkers) {
        assert.ok(output.includes(marker), `staging-evidence-gap-report output must include ${marker}`);
      }
    }
    if (result.id === 'obsidian-readiness-snapshot-check') {
      const output = `${result.stdout_tail}\n${result.stderr_tail}`;
      assert.match(output, /Obsidian readiness snapshot is in sync: .*:/, 'obsidian-readiness-snapshot-check output must include the Obsidian readiness proof summary');
      for (const marker of obsidianReadinessProofMarkers) {
        assert.ok(output.includes(marker), `obsidian-readiness-snapshot-check output must include ${marker}`);
      }
    }
  }

  if (requireAllGates) {
    for (const gateID of requiredGateIds) {
      assert.ok(seen.has(gateID), `local gate report missing ${gateID}`);
    }
  }

  return {
    gateCount: report.results.length,
    dryRun: report.dry_run,
    gitHead: report.git_head,
    gitBranch: report.git_branch,
  };
}

export function parseArgs(argv) {
  const args = {
    report: 'artifacts/local-gate-report.json',
    allowDryRun: false,
    requireAllGates: true,
    allowDirty: false,
    allowUnsynced: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--report') {
      args.report = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--allow-dry-run') {
      args.allowDryRun = true;
    } else if (argv[i] === '--allow-subset') {
      args.requireAllGates = false;
    } else if (argv[i] === '--allow-dirty') {
      args.allowDirty = true;
    } else if (argv[i] === '--allow-unsynced') {
      args.allowUnsynced = true;
    } else {
      throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  return args;
}

function commandDisplay(gate) {
  const prefix = gate.cwd ? `(cd ${gate.cwd}) ` : '';
  const envPrefix = gate.env
    ? `${Object.entries(gate.env).map(([key, value]) => `${key}=${value}`).join(' ')} `
    : '';
  return `${prefix}${envPrefix}${gate.command.join(' ')}`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = JSON.parse(await readFile(args.report, 'utf8'));
  const result = validateLocalGateReport(report, args);
  console.log(`local gate report validated: ${args.report} (${result.gateCount} gates)`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-local-gate-report.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
