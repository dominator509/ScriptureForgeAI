import assert from 'node:assert/strict';
import test from 'node:test';
import { clientCommandProofMarkers } from './run-client-command.mjs';
import { goTestProofMarkers, goVetProofMarkers } from './run-go-core-gate.mjs';
import { goProbeProofMarkers } from './run-go-probe-tests.mjs';
import { ciEvidenceGateProofMarkers } from './validate-ci-evidence-gates.mjs';
import { ciWorkflowProofMarkers, requiredMarkers as ciWorkflowRequiredMarkers } from './validate-ci-workflow.mjs';
import { dependencyRiskProofMarkers } from './validate-dependency-risk.mjs';
import { deploymentSkeletonProofMarkers } from './validate-deployment-skeleton.mjs';
import { journalCryptoProofMarkers } from './verify-journal-crypto.mjs';
import { observabilityProofMarkers } from './validate-observability.mjs';
import { gateDefinitions } from './run-local-gates.mjs';
import { npmAuditProofMarkers } from './run-npm-audit.mjs';
import { rustCargoProofMarkers } from './run-rust-cargo-gate.mjs';
import { terraformFmtProofMarkers, terraformValidateProofMarkers } from './run-terraform-command.mjs';
import { terraformInitProofMarkers } from './run-terraform-init.mjs';
import { rlsDBProofMarkers } from './run-rls-db-integration.mjs';
import { parseArgs, validateLocalGateReport } from './validate-local-gate-report.mjs';
import { rustProtobufProofMarkers } from './verify-rust-protobuf.mjs';
import { securityArtifactsProofMarkers } from './validate-security-artifacts.mjs';
import { secretHygieneProofMarkers } from './validate-secret-hygiene.mjs';
import { stagingEvidenceContractProofMarkers } from './sync-staging-evidence-contract.mjs';
import { stagingEvidenceProofMarkers } from './validate-staging-evidence.mjs';
import { obsidianReadinessProofMarkers } from './sync-obsidian-readiness.mjs';
import { stagingEvidenceGapReportProofMarkers } from './report-staging-evidence-gaps.mjs';
import { ciReleaseEvidenceProofMarkers } from './write-ci-release-evidence.mjs';
import { projectPathProofMarkers, strictStagingPathProofMarkers } from './verify-project-path.mjs';

test('parseArgs supports report path and relaxed validation flags', () => {
  const args = parseArgs(['--report', 'artifacts/report.json', '--allow-dry-run', '--allow-subset', '--allow-dirty', '--allow-unsynced']);
  assert.equal(args.report, 'artifacts/report.json');
  assert.equal(args.allowDryRun, true);
  assert.equal(args.requireAllGates, false);
  assert.equal(args.allowDirty, true);
  assert.equal(args.allowUnsynced, true);
});

test('validateLocalGateReport accepts a complete passing report', () => {
  const report = completeReport();
  const result = validateLocalGateReport(report);
  assert.equal(result.gateCount, gateDefinitions.length);
  assert.equal(result.dryRun, false);
  assert.equal(result.gitHead, '0123456789abcdef0123456789abcdef01234567');
});

test('validateLocalGateReport rejects dry-run reports unless allowed', () => {
  const report = completeReport({ dryRun: true });
  assert.throws(() => validateLocalGateReport(report), /dry-run/);
  assert.doesNotThrow(() => validateLocalGateReport(report, { allowDryRun: true }));
});

test('validateLocalGateReport rejects individually skipped gates in release evidence', () => {
  const report = completeReport({ skippedGateID: 'rls-db-integration' });
  assert.throws(
    () => validateLocalGateReport(report),
    /rls-db-integration must not be skipped/,
  );
});

test('validateLocalGateReport rejects stale or weakened canonical gate commands', () => {
  const report = completeReport();
  findGate(report, 'go-test').command = 'go test ./cmd/platform-engine';
  assert.throws(
    () => validateLocalGateReport(report),
    /go-test command must match the canonical local gate command/,
  );
});

test('validateLocalGateReport rejects Go core gates without wrapper proof markers', () => {
  const missingTestSummary = completeReport();
  findGate(missingTestSummary, 'go-test').stdout_tail = 'ok scriptureforge/internal/ports';
  assert.throws(
    () => validateLocalGateReport(missingTestSummary),
    /go-test output must include the Go test proof summary/,
  );

  const missingTestMarker = completeReport();
  findGate(missingTestMarker, 'go-test').stdout_tail = goTestProofOutput()
    .replace('go_timeout_90s=true', 'go_timeout_90s=false');
  assert.throws(
    () => validateLocalGateReport(missingTestMarker),
    /go-test output must include go_timeout_90s=true/,
  );

  const missingWebSocketMarker = completeReport();
  findGate(missingWebSocketMarker, 'go-test').stdout_tail = goTestProofOutput()
    .replace('websocket_realtime_tests_passed=true', 'websocket_realtime_tests_passed=false');
  assert.throws(
    () => validateLocalGateReport(missingWebSocketMarker),
    /go-test output must include websocket_realtime_tests_passed=true/,
  );

  const missingVetSummary = completeReport();
  findGate(missingVetSummary, 'go-vet').stdout_tail = '';
  assert.throws(
    () => validateLocalGateReport(missingVetSummary),
    /go-vet output must include the Go vet proof summary/,
  );

  const missingVetMarker = completeReport();
  findGate(missingVetMarker, 'go-vet').stdout_tail = goVetProofOutput()
    .replace('go_static_analysis=true', 'go_static_analysis=false');
  assert.throws(
    () => validateLocalGateReport(missingVetMarker),
    /go-vet output must include go_static_analysis=true/,
  );
});

test('validateLocalGateReport rejects weakened RLS DB integration evidence command', () => {
  const missingRequire = completeReport();
  findGate(missingRequire, 'rls-db-integration').command = 'GOCACHE=.gocache node tools/run-rls-db-integration.mjs';
  assert.throws(
    () => validateLocalGateReport(missingRequire),
    /rls-db-integration command must match the canonical local gate command/,
  );

  const genericGoTest = completeReport();
  findGate(genericGoTest, 'rls-db-integration').command = 'GOCACHE=.gocache REQUIRE_DATABASE_URL=true go test ./tests/integration';
  assert.throws(
    () => validateLocalGateReport(genericGoTest),
    /rls-db-integration command must match the canonical local gate command/,
  );
});

test('validateLocalGateReport rejects RLS DB reports without semantic proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'rls-db-integration').stdout_tail = 'ok scriptureforge/tests/integration';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /rls-db-integration output must include the DB-backed proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'rls-db-integration').stdout_tail = rlsProofOutput()
    .replace('TenantScopedJournalHandlersEnforceRLS', 'TenantScopedJournalHandlers');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /rls-db-integration output must include TenantScopedJournalHandlersEnforceRLS/,
  );

  const missingSemanticMarker = completeReport();
  findGate(missingSemanticMarker, 'rls-db-integration').stdout_tail = rlsProofOutput()
    .replace(', rls_table_journal_entries=true', '');
  assert.throws(
    () => validateLocalGateReport(missingSemanticMarker),
    /rls-db-integration output must include rls_table_journal_entries=true/,
  );

  const missingHandlerWriteMarker = completeReport();
  findGate(missingHandlerWriteMarker, 'rls-db-integration').stdout_tail = rlsProofOutput()
    .replace(', journal_handler_cross_tenant_write_denied=true', '');
  assert.throws(
    () => validateLocalGateReport(missingHandlerWriteMarker),
    /rls-db-integration output must include journal_handler_cross_tenant_write_denied=true/,
  );
});

test('validateLocalGateReport rejects production evidence probe reports without wrapper proof markers', () => {
  const rawCommand = completeReport();
  findGate(rawCommand, 'evidence-probes').command = 'GOCACHE=.gocache go test ./tools/ciprobe ./tools/stagingprobe ./tools/tenantprobe -count=1';
  assert.throws(
    () => validateLocalGateReport(rawCommand),
    /evidence-probes command must match the canonical local gate command/,
  );

  const missingSummary = completeReport();
  findGate(missingSummary, 'evidence-probes').stdout_tail = 'ok scriptureforge/tools/zoomprobe';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /evidence-probes output must include the production evidence probe proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'evidence-probes').stdout_tail = goProbeProofOutput()
    .replace('zoomprobe_tests=true', 'zoomprobe_tests=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /evidence-probes output must include zoomprobe_tests=true/,
  );
});

test('validateLocalGateReport rejects npm audit gates without proof markers', () => {
  const missingWebSummary = completeReport();
  findGate(missingWebSummary, 'web-audit').stdout_tail = '';
  assert.throws(
    () => validateLocalGateReport(missingWebSummary),
    /web-audit output must include the npm audit proof summary/,
  );

  const missingMobileMarker = completeReport();
  findGate(missingMobileMarker, 'mobile-audit').stdout_tail = npmAuditProofOutput()
    .replace('audit_level_enforced=true', 'audit_level_enforced=false');
  assert.throws(
    () => validateLocalGateReport(missingMobileMarker),
    /mobile-audit output must include audit_level_enforced=true/,
  );
});

test('validateLocalGateReport rejects client smoke reports without product-flow proof markers', () => {
  const missingWebSummary = completeReport();
  findGate(missingWebSummary, 'web-smoke').stdout_tail = 'web smoke passed';
  assert.throws(
    () => validateLocalGateReport(missingWebSummary),
    /web-smoke output must include the web API smoke proof summary/,
  );

  const missingWebMarker = completeReport();
  findGate(missingWebMarker, 'web-smoke').stdout_tail = webSmokeProofOutput()
    .replace('web_crypto_key_disposal=true', 'web_crypto_key_disposal=false');
  assert.throws(
    () => validateLocalGateReport(missingWebMarker),
    /web-smoke output must include web_crypto_key_disposal=true/,
  );

  const missingMobileSummary = completeReport();
  findGate(missingMobileSummary, 'mobile-smoke').stdout_tail = 'mobile smoke passed';
  assert.throws(
    () => validateLocalGateReport(missingMobileSummary),
    /mobile-smoke output must include the mobile API smoke proof summary/,
  );

  const missingMobileMarker = completeReport();
  findGate(missingMobileMarker, 'mobile-smoke').stdout_tail = mobileSmokeProofOutput()
    .replace('mobile_crypto_native_required_fail_closed=true', 'mobile_crypto_native_required_fail_closed=false');
  assert.throws(
    () => validateLocalGateReport(missingMobileMarker),
    /mobile-smoke output must include mobile_crypto_native_required_fail_closed=true/,
  );
});

test('validateLocalGateReport rejects client build reports without wrapper proof markers', () => {
  const missingWebTypecheckSummary = completeReport();
  findGate(missingWebTypecheckSummary, 'web-typecheck').stdout_tail = 'tsc passed';
  assert.throws(
    () => validateLocalGateReport(missingWebTypecheckSummary),
    /web-typecheck output must include the web typecheck proof summary/,
  );

  const missingWebTypecheckMarker = completeReport();
  findGate(missingWebTypecheckMarker, 'web-typecheck').stdout_tail = webTypecheckProofOutput()
    .replace('web_runtime_types=true', 'web_runtime_types=false');
  assert.throws(
    () => validateLocalGateReport(missingWebTypecheckMarker),
    /web-typecheck output must include web_runtime_types=true/,
  );

  const missingWebBuildSummary = completeReport();
  findGate(missingWebBuildSummary, 'web-build').stdout_tail = 'next build passed';
  assert.throws(
    () => validateLocalGateReport(missingWebBuildSummary),
    /web-build output must include the web build proof summary/,
  );

  const missingWebBuildMarker = completeReport();
  findGate(missingWebBuildMarker, 'web-build').stdout_tail = webBuildProofOutput()
    .replace('web_production_bundle=true', 'web_production_bundle=false');
  assert.throws(
    () => validateLocalGateReport(missingWebBuildMarker),
    /web-build output must include web_production_bundle=true/,
  );

  const missingMobileBuildSummary = completeReport();
  findGate(missingMobileBuildSummary, 'mobile-build-check').stdout_tail = 'mobile build check passed';
  assert.throws(
    () => validateLocalGateReport(missingMobileBuildSummary),
    /mobile-build-check output must include the mobile build-check proof summary/,
  );

  const missingMobileBuildMarker = completeReport();
  findGate(missingMobileBuildMarker, 'mobile-build-check').stdout_tail = mobileBuildCheckProofOutput()
    .replace('mobile_crypto_verification=true', 'mobile_crypto_verification=false');
  assert.throws(
    () => validateLocalGateReport(missingMobileBuildMarker),
    /mobile-build-check output must include mobile_crypto_verification=true/,
  );
});

test('validateLocalGateReport rejects Rust reports without protobuf or Cargo proof markers', () => {
  const missingProtobufSummary = completeReport();
  findGate(missingProtobufSummary, 'rust-protobuf-validation').stdout_tail = 'protobuf ok';
  assert.throws(
    () => validateLocalGateReport(missingProtobufSummary),
    /rust-protobuf-validation output must include the verifier proof summary/,
  );

  const missingProtobufMarker = completeReport();
  findGate(missingProtobufMarker, 'rust-protobuf-validation').stdout_tail = rustProtobufProofOutput()
    .replace('generated_types_covered=true', 'generated_types_covered=false');
  assert.throws(
    () => validateLocalGateReport(missingProtobufMarker),
    /rust-protobuf-validation output must include generated_types_covered=true/,
  );

  const missingCargoMarker = completeReport();
  findGate(missingCargoMarker, 'rust-cargo-test').stdout_tail = rustCargoProofOutput()
    .replace('generated_vector_search_response_holds_results', 'generated_vector_search_response');
  assert.throws(
    () => validateLocalGateReport(missingCargoMarker),
    /rust-cargo-test output must include generated_vector_search_response_holds_results/,
  );

  const missingGrpcTypeMarker = completeReport();
  findGate(missingGrpcTypeMarker, 'rust-cargo-test').stdout_tail = rustCargoProofOutput()
    .replace('generated_grpc_client_and_server_types_compile', 'generated_grpc_client_server_types');
  assert.throws(
    () => validateLocalGateReport(missingGrpcTypeMarker),
    /rust-cargo-test output must include generated_grpc_client_and_server_types_compile/,
  );
});

test('validateLocalGateReport rejects Terraform init reports without proof markers', () => {
  const missingFmtSummary = completeReport();
  findGate(missingFmtSummary, 'terraform-fmt').stdout_tail = '';
  assert.throws(
    () => validateLocalGateReport(missingFmtSummary),
    /terraform-fmt output must include the Terraform fmt proof summary/,
  );

  const missingFmtMarker = completeReport();
  findGate(missingFmtMarker, 'terraform-fmt').stdout_tail = terraformFmtProofOutput()
    .replace('recursive_fmt_check=true', 'recursive_fmt_check=false');
  assert.throws(
    () => validateLocalGateReport(missingFmtMarker),
    /terraform-fmt output must include recursive_fmt_check=true/,
  );

  const missingSummary = completeReport();
  findGate(missingSummary, 'terraform-init-validate').stdout_tail = 'Terraform initialized';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /terraform-init-validate output must include the Terraform init proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'terraform-init-validate').stdout_tail = terraformInitProofOutput()
    .replace('backend_false_default=true', 'backend_false_default=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /terraform-init-validate output must include backend_false_default=true/,
  );

  const missingValidateSummary = completeReport();
  findGate(missingValidateSummary, 'terraform-validate').stdout_tail = 'Success! The configuration is valid.';
  assert.throws(
    () => validateLocalGateReport(missingValidateSummary),
    /terraform-validate output must include the Terraform validate proof summary/,
  );

  const missingValidateMarker = completeReport();
  findGate(missingValidateMarker, 'terraform-validate').stdout_tail = terraformValidateProofOutput()
    .replace('validated_skeleton=true', 'validated_skeleton=false');
  assert.throws(
    () => validateLocalGateReport(missingValidateMarker),
    /terraform-validate output must include validated_skeleton=true/,
  );
});

test('validateLocalGateReport rejects deployment skeleton reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'deployment-skeleton-validation').stdout_tail = 'deployment skeleton ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /deployment-skeleton-validation output must include the deployment proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'deployment-skeleton-validation').stdout_tail = deploymentSkeletonProofOutput()
    .replace('secretproviderclass_sync=true', 'secretproviderclass_sync=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /deployment-skeleton-validation output must include secretproviderclass_sync=true/,
  );
});

test('validateLocalGateReport rejects observability reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'observability-validation').stdout_tail = 'observability ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /observability-validation output must include the observability proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'observability-validation').stdout_tail = observabilityProofOutput()
    .replace('dependency_spans=true', 'dependency_spans=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /observability-validation output must include dependency_spans=true/,
  );
});

test('validateLocalGateReport rejects journal crypto reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'journal-crypto-validation').stdout_tail = 'journal crypto ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /journal-crypto-validation output must include the journal crypto proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'journal-crypto-validation').stdout_tail = journalCryptoProofOutput()
    .replace('associated_data_rejected=true', 'associated_data_rejected=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /journal-crypto-validation output must include associated_data_rejected=true/,
  );
});

test('validateLocalGateReport rejects security artifact reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'security-artifacts-validation').stdout_tail = 'security artifacts ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /security-artifacts-validation output must include the security artifacts proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'security-artifacts-validation').stdout_tail = securityArtifactsProofOutput()
    .replace('secret_handling_review=true', 'secret_handling_review=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /security-artifacts-validation output must include secret_handling_review=true/,
  );
});

test('validateLocalGateReport rejects dependency risk reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'dependency-risk-validation').stdout_tail = 'dependency risk ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /dependency-risk-validation output must include the dependency risk proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'dependency-risk-validation').stdout_tail = dependencyRiskProofOutput()
    .replace('drr001_review_current=true', 'drr001_review_current=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /dependency-risk-validation output must include drr001_review_current=true/,
  );
});

test('validateLocalGateReport rejects secret hygiene reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'secret-hygiene-validation').stdout_tail = 'secret hygiene ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /secret-hygiene-validation output must include the secret hygiene proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'secret-hygiene-validation').stdout_tail = secretHygieneProofOutput()
    .replace('plaintext_secret_findings_zero=true', 'plaintext_secret_findings_zero=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /secret-hygiene-validation output must include plaintext_secret_findings_zero=true/,
  );
});

test('validateLocalGateReport rejects CI workflow reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'ci-workflow-validation').stdout_tail = 'CI workflow ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /ci-workflow-validation output must include the CI workflow proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'ci-workflow-validation').stdout_tail = ciWorkflowProofOutput()
    .replace('release_evidence_write_validate_upload_order=true', 'release_evidence_write_validate_upload_order=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /ci-workflow-validation output must include release_evidence_write_validate_upload_order=true/,
  );

  const missingGapReportMarker = completeReport();
  findGate(missingGapReportMarker, 'ci-workflow-validation').stdout_tail = ciWorkflowProofOutput()
    .replace('staging_evidence_gap_report_check=true', 'staging_evidence_gap_report_check=false');
  assert.throws(
    () => validateLocalGateReport(missingGapReportMarker),
    /ci-workflow-validation output must include staging_evidence_gap_report_check=true/,
  );
});

test('validateLocalGateReport rejects CI evidence gate reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'ci-evidence-gate-validation').stdout_tail = 'CI evidence gates ok';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /ci-evidence-gate-validation output must include the CI evidence gate proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'ci-evidence-gate-validation').stdout_tail = ciEvidenceGateProofOutput()
    .replace('ciprobe_required_gate_markers_mirrored=true', 'ciprobe_required_gate_markers_mirrored=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /ci-evidence-gate-validation output must include ciprobe_required_gate_markers_mirrored=true/,
  );

  const missingProofMarkerCount = completeReport();
  findGate(missingProofMarkerCount, 'ci-evidence-gate-validation').stdout_tail = ciEvidenceGateProofOutput()
    .replace(/ and \d+ proof markers/, '');
  assert.throws(
    () => validateLocalGateReport(missingProofMarkerCount),
    /ci-evidence-gate-validation output must include the CI evidence gate proof summary with required-entry and proof-marker counts/,
  );
});

test('validateLocalGateReport rejects PATH readiness gates without proof markers', () => {
  const missingLocalMarker = completeReport();
  findGate(missingLocalMarker, 'project-path-readiness').stdout_tail = 'ScriptureForgeAI PATH readiness\nmode: local\nrequired: 8/8\n';
  assert.throws(
    () => validateLocalGateReport(missingLocalMarker),
    /project-path-readiness output must include PATH proof markers/,
  );

  const missingStrictMarker = completeReport();
  findGate(missingStrictMarker, 'strict-staging-path-readiness').stdout_tail = projectPathProofOutput('staging-evidence')
    .replace('strict_staging_tools_resolved=true', 'strict_staging_tools_resolved=false');
  assert.throws(
    () => validateLocalGateReport(missingStrictMarker),
    /strict-staging-path-readiness output must include strict_staging_tools_resolved=true/,
  );
});

test('validateLocalGateReport rejects staging evidence contract reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'staging-evidence-contract-check').stdout_tail = 'Staging evidence contract is in sync';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /staging-evidence-contract-check output must include the staging evidence contract proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'staging-evidence-contract-check').stdout_tail = stagingEvidenceContractProofOutput()
    .replace('pending_external_required_evidence_checked=true', 'pending_external_required_evidence_checked=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /staging-evidence-contract-check output must include pending_external_required_evidence_checked=true/,
  );
});

test('validateLocalGateReport rejects staging evidence reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'staging-evidence-validation').stdout_tail = 'staging evidence manifest validated';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /staging-evidence-validation output must include the staging evidence proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'staging-evidence-validation').stdout_tail = stagingEvidenceProofOutput()
    .replace('strict_release_candidate_markers_checked=true', 'strict_release_candidate_markers_checked=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /staging-evidence-validation output must include strict_release_candidate_markers_checked=true/,
  );

  const missingNumericMarker = completeReport();
  findGate(missingNumericMarker, 'staging-evidence-validation').stdout_tail = stagingEvidenceProofOutput()
    .replace('strict_numeric_thresholds_checked=true', 'strict_numeric_thresholds_checked=false');
  assert.throws(
    () => validateLocalGateReport(missingNumericMarker),
    /staging-evidence-validation output must include strict_numeric_thresholds_checked=true/,
  );
});

test('validateLocalGateReport rejects staging evidence gap reports without proof markers or allow-blockers mode', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'staging-evidence-gap-report').stdout_tail = 'strict release ready: no';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /staging-evidence-gap-report output must include the not-ready proof footer/,
  );

  const missingFooterCounts = completeReport();
  findGate(missingFooterCounts, 'staging-evidence-gap-report').stdout_tail = stagingEvidenceGapReportProofOutput()
    .replace(/, counts=[^,]+, proof_markers=/, ', proof_markers=');
  assert.throws(
    () => validateLocalGateReport(missingFooterCounts),
    /staging-evidence-gap-report output must include status counts in the proof footer/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'staging-evidence-gap-report').stdout_tail = stagingEvidenceGapReportProofOutput()
    .replaceAll('blocking_items_listed=true', '');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /staging-evidence-gap-report output must include blocking_items_listed=true/,
  );

  const missingRequiredEvidence = completeReport();
  findGate(missingRequiredEvidence, 'staging-evidence-gap-report').stdout_tail = stagingEvidenceGapReportProofOutput()
    .replace('\n  required: uploaded ci-release-evidence artifact for SRC-CI-001', '');
  assert.throws(
    () => validateLocalGateReport(missingRequiredEvidence),
    /staging-evidence-gap-report output must preserve rendered required-evidence details/,
  );

  const mismatchedBlockingCount = completeReport();
  findGate(mismatchedBlockingCount, 'staging-evidence-gap-report').stdout_tail = stagingEvidenceGapReportProofOutput()
    .replace('blocking_items=1', 'blocking_items=2');
  assert.throws(
    () => validateLocalGateReport(mismatchedBlockingCount),
    /blocking item IDs must match the proof footer count/,
  );

  const missingAllowBlockers = completeReport();
  findGate(missingAllowBlockers, 'staging-evidence-gap-report').command = 'node tools/report-staging-evidence-gaps.mjs --manifest production-readiness/staging-evidence.example.json';
  assert.throws(
    () => validateLocalGateReport(missingAllowBlockers),
    /command must match the canonical local gate command/,
  );
});

test('validateLocalGateReport rejects Obsidian readiness snapshot reports without proof markers', () => {
  const missingSummary = completeReport();
  findGate(missingSummary, 'obsidian-readiness-snapshot-check').stdout_tail = 'Obsidian readiness snapshot is in sync';
  assert.throws(
    () => validateLocalGateReport(missingSummary),
    /obsidian-readiness-snapshot-check output must include the Obsidian readiness proof summary/,
  );

  const missingMarker = completeReport();
  findGate(missingMarker, 'obsidian-readiness-snapshot-check').stdout_tail = obsidianReadinessProofOutput()
    .replace('snapshot_body_current=true', 'snapshot_body_current=false');
  assert.throws(
    () => validateLocalGateReport(missingMarker),
    /obsidian-readiness-snapshot-check output must include snapshot_body_current=true/,
  );
});

test('validateLocalGateReport rejects failed or incomplete reports', () => {
  assert.throws(
    () => validateLocalGateReport(completeReport({ failedGateID: 'go-vet' })),
    /threshold_pass must be true/,
  );
  assert.throws(
    () => validateLocalGateReport(partialReport()),
    /gates_total must match results length/,
  );
});

test('validateLocalGateReport rejects missing git head', () => {
  const report = completeReport();
  delete report.git_head;
  assert.throws(() => validateLocalGateReport(report), /git_head/);
});

test('validateLocalGateReport rejects reports observed after validation date', () => {
  const report = completeReport();
  report.observed_at = '2026-06-26T00:00:00Z';
  assert.throws(
    () => validateLocalGateReport(report, { today: '2026-06-25' }),
    /local gate report observed_at must not be after validation date/,
  );
});

test('validateLocalGateReport rejects invalid validation date input', () => {
  const report = completeReport();
  assert.throws(
    () => validateLocalGateReport(report, { today: 'not-a-date' }),
    /today must be YYYY-MM-DD/,
  );
});

test('validateLocalGateReport rejects dirty or unsynced git state unless allowed', () => {
  const dirty = completeReport({ gitStatusClean: false, gitStatusShort: ' M README.md' });
  assert.throws(() => validateLocalGateReport(dirty), /clean worktree/);
  assert.doesNotThrow(() => validateLocalGateReport(dirty, { allowDirty: true }));

  const ahead = completeReport({ gitAhead: 1 });
  assert.throws(() => validateLocalGateReport(ahead), /must not be ahead/);
  assert.doesNotThrow(() => validateLocalGateReport(ahead, { allowUnsynced: true }));

  const missingUpstream = completeReport({ gitUpstream: '' });
  assert.throws(() => validateLocalGateReport(missingUpstream), /requires an upstream/);
  assert.doesNotThrow(() => validateLocalGateReport(missingUpstream, { allowUnsynced: true }));
});

test('validateLocalGateReport can validate focused subset reports', () => {
  const report = partialReport({ consistentTotals: true });
  assert.throws(() => validateLocalGateReport(report), /missing/);
  assert.doesNotThrow(() => validateLocalGateReport(report, { requireAllGates: false }));
});

function completeReport({ dryRun = false, failedGateID = '', skippedGateID = '', gitStatusClean = true, gitStatusShort = '', gitAhead = 0, gitBehind = 0, gitUpstream = 'origin/codex/production-readiness-remediation' } = {}) {
  const results = gateDefinitions.map((gate, index) => ({
    id: gate.id,
    command: testCommandDisplay(gate),
    cwd: gate.cwd ?? '.',
    skipped: dryRun || gate.id === skippedGateID,
    exit_code: gate.id === failedGateID ? 1 : 0,
    duration_ms: index,
    stdout_tail: stdoutForGate(gate.id),
    stderr_tail: '',
  }));
  const failed = results.filter((result) => result.exit_code !== 0).length;
  return {
    schema_version: 1,
    git_head: '0123456789abcdef0123456789abcdef01234567',
    git_branch: 'codex/production-readiness-remediation',
    git_upstream: gitUpstream,
    git_ahead: gitAhead,
    git_behind: gitBehind,
    git_status_clean: gitStatusClean,
    git_status_short: gitStatusShort,
    observed_at: '2026-06-25T12:00:00Z',
    duration_ms: 100,
    threshold_pass: failed === 0,
    dry_run: dryRun,
    gates_total: results.length,
    gates_run: results.length,
    gates_failed: failed,
    results,
  };
}

function rlsProofOutput() {
  return `rls-db-integration proof: ${rlsDBProofMarkers.join(', ')}`;
}

function goTestProofOutput() {
  return `go-test-gate validated: ${goTestProofMarkers.join(', ')}`;
}

function goVetProofOutput() {
  return `go-vet-gate validated: ${goVetProofMarkers.join(', ')}`;
}

function goProbeProofOutput() {
  return `production evidence probe tests validated: ${goProbeProofMarkers.join(', ')}`;
}

function npmAuditProofOutput() {
  return `npm audit gate validated: ${npmAuditProofMarkers.join(', ')}`;
}

function terraformInitProofOutput() {
  return `terraform init gate validated: ${terraformInitProofMarkers.join(', ')}`;
}

function terraformFmtProofOutput() {
  return `terraform-fmt-gate validated: ${terraformFmtProofMarkers.join(', ')}`;
}

function terraformValidateProofOutput() {
  return `terraform-validate-gate validated: ${terraformValidateProofMarkers.join(', ')}`;
}

function webSmokeProofOutput() {
  return [
    'web api smoke proof: web_api_auth_routes=true, web_api_encrypted_journal=true, web_api_rooms_ws=true, web_runtime_strict_endpoint_guard=true',
    'web crypto smoke proof: web_crypto_aes_gcm=true, web_crypto_unique_iv=true, web_crypto_associated_data=true, web_crypto_pbkdf2_600000=true, web_crypto_key_disposal=true',
  ].join('\n');
}

function webTypecheckProofOutput() {
  return `web-typecheck-gate validated: ${[
    ...clientCommandProofMarkers,
    'web_typescript_no_emit=true',
    'web_runtime_types=true',
  ].join(', ')}`;
}

function webBuildProofOutput() {
  return `web-build-gate validated: ${[
    ...clientCommandProofMarkers,
    'next_build=true',
    'web_production_bundle=true',
  ].join(', ')}`;
}

function mobileSmokeProofOutput() {
  return [
    'mobile api smoke proof: mobile_api_auth_mfa=true, mobile_api_encrypted_journal=true, mobile_api_rooms_ws=true, mobile_runtime_native_required_guard=true',
    'mobile crypto smoke proof: mobile_crypto_aes_gcm=true, mobile_crypto_associated_data=true, mobile_crypto_native_required_fail_closed=true, mobile_crypto_self_test_markers=true',
  ].join('\n');
}

function mobileBuildCheckProofOutput() {
  return `mobile-build-check-gate validated: ${[
    ...clientCommandProofMarkers,
    'mobile_typecheck=true',
    'mobile_smoke=true',
    'mobile_crypto_verification=true',
  ].join(', ')}`;
}

function rustProtobufProofOutput() {
  return `Rust protobuf tooling verified: ${rustProtobufProofMarkers.join(', ')}`;
}

function rustCargoProofOutput() {
  return `rust-cargo-test validated: ${rustCargoProofMarkers.join(', ')}`;
}

function deploymentSkeletonProofOutput() {
  return `deployment skeleton and runtime config invariants validated: ${deploymentSkeletonProofMarkers.join(', ')}`;
}

function observabilityProofOutput() {
  return `observability artifacts validated: ${observabilityProofMarkers.join(', ')}`;
}

function journalCryptoProofOutput() {
  return `journal crypto verification passed: ${journalCryptoProofMarkers.join(', ')}`;
}

function securityArtifactsProofOutput() {
  return `security artifacts validated: ${securityArtifactsProofMarkers.join(', ')}`;
}

function dependencyRiskProofOutput() {
  return `dependency risk validated: uuid 7.0.3, expo 56.0.12, DRR-001 required=true, ${dependencyRiskProofMarkers.join(', ')}`;
}

function secretHygieneProofOutput() {
  return `secret hygiene validated across 500 text files: ${secretHygieneProofMarkers.join(', ')}`;
}

function ciWorkflowProofOutput() {
  return `CI workflow validated: .github/workflows/security.yml (${ciWorkflowRequiredMarkers.length} required markers): ${ciWorkflowProofMarkers.join(', ')}`;
}

function ciEvidenceGateProofOutput() {
  return `CI evidence gate markers validated across ${gateDefinitions.length + 1} required entries and ${ciReleaseEvidenceProofMarkers.length + 1} proof markers: ${ciEvidenceGateProofMarkers.join(', ')}`;
}

function stagingEvidenceContractProofOutput() {
  return `Staging evidence contract is in sync: production-readiness/staging-evidence.staging.json: ${stagingEvidenceContractProofMarkers.join(', ')}`;
}

function stagingEvidenceProofOutput() {
  return `staging evidence manifest validated: production-readiness/staging-evidence.example.json (21 items): ${stagingEvidenceProofMarkers.join(', ')}`;
}

function stagingEvidenceGapReportProofOutput() {
  return [
    'staging evidence gaps for staging (0123456789abcdef0123456789abcdef01234567)',
    'status counts: passed=20, pending_external=1, blocked=0, failed=0, accepted_risk=0',
    'non-manifest blockers: 0',
    'strict release ready: no',
    `proof markers: ${stagingEvidenceGapReportProofMarkers.join(', ')}`,
    'blocking items:',
    '- SRC-CI-001 [pending_external] Clean pushed GitHub Actions run for the exact release SHA.',
    '  required: uploaded ci-release-evidence artifact for SRC-CI-001',
    `gap report proof footer: strict_release_ready=no, strict_staging_path_ready=yes, blocking_items=1, blocking_item_ids=SRC-CI-001, counts=passed:20|pending_external:1|blocked:0|failed:0|accepted_risk:0|non_manifest:0, proof_markers=${stagingEvidenceGapReportProofMarkers.join(', ')}`,
  ].join('\n');
}

function obsidianReadinessProofOutput() {
  return `Obsidian readiness snapshot is in sync: production-readiness/obsidian-production-readiness.md: ${obsidianReadinessProofMarkers.join(', ')}`;
}

function projectPathProofOutput(mode) {
  const markers = mode === 'staging-evidence' ? strictStagingPathProofMarkers : projectPathProofMarkers;
  return `ScriptureForgeAI PATH readiness\nmode: ${mode}\nrequired: 8/8\npath readiness proof: ${markers.join(', ')}`;
}

function stdoutForGate(id) {
  if (id === 'project-path-readiness') return projectPathProofOutput('local');
  if (id === 'strict-staging-path-readiness') return projectPathProofOutput('staging-evidence');
  if (id === 'go-test') return goTestProofOutput();
  if (id === 'go-vet') return goVetProofOutput();
  if (id === 'rls-db-integration') return rlsProofOutput();
  if (id === 'evidence-probes') return goProbeProofOutput();
  if (id === 'web-audit' || id === 'mobile-audit') return npmAuditProofOutput();
  if (id === 'web-smoke') return webSmokeProofOutput();
  if (id === 'web-typecheck') return webTypecheckProofOutput();
  if (id === 'web-build') return webBuildProofOutput();
  if (id === 'mobile-smoke') return mobileSmokeProofOutput();
  if (id === 'mobile-build-check') return mobileBuildCheckProofOutput();
  if (id === 'rust-protobuf-validation') return rustProtobufProofOutput();
  if (id === 'rust-cargo-test') return rustCargoProofOutput();
  if (id === 'terraform-fmt') return terraformFmtProofOutput();
  if (id === 'terraform-init-validate') return terraformInitProofOutput();
  if (id === 'terraform-validate') return terraformValidateProofOutput();
  if (id === 'deployment-skeleton-validation') return deploymentSkeletonProofOutput();
  if (id === 'observability-validation') return observabilityProofOutput();
  if (id === 'journal-crypto-validation') return journalCryptoProofOutput();
  if (id === 'security-artifacts-validation') return securityArtifactsProofOutput();
  if (id === 'dependency-risk-validation') return dependencyRiskProofOutput();
  if (id === 'secret-hygiene-validation') return secretHygieneProofOutput();
  if (id === 'ci-workflow-validation') return ciWorkflowProofOutput();
  if (id === 'ci-evidence-gate-validation') return ciEvidenceGateProofOutput();
  if (id === 'staging-evidence-contract-check') return stagingEvidenceContractProofOutput();
  if (id === 'staging-evidence-validation') return stagingEvidenceProofOutput();
  if (id === 'staging-evidence-gap-report') return stagingEvidenceGapReportProofOutput();
  if (id === 'obsidian-readiness-snapshot-check') return obsidianReadinessProofOutput();
  return '';
}

function findGate(report, id) {
  const gate = report.results.find((result) => result.id === id);
  assert.ok(gate, `missing gate ${id}`);
  return gate;
}

function testCommandDisplay(gate) {
  const prefix = gate.cwd ? `(cd ${gate.cwd}) ` : '';
  const envPrefix = gate.env
    ? `${Object.entries(gate.env).map(([key, value]) => `${key}=${value}`).join(' ')} `
    : '';
  return `${prefix}${envPrefix}${gate.command.join(' ')}`;
}

function partialReport({ consistentTotals = false } = {}) {
  const results = completeReport().results.slice(0, 2);
  return {
    schema_version: 1,
    git_head: '0123456789abcdef0123456789abcdef01234567',
    git_branch: 'codex/production-readiness-remediation',
    git_upstream: 'origin/codex/production-readiness-remediation',
    git_ahead: 0,
    git_behind: 0,
    git_status_clean: true,
    git_status_short: '',
    observed_at: '2026-06-25T12:00:00Z',
    duration_ms: 100,
    threshold_pass: true,
    dry_run: false,
    gates_total: consistentTotals ? results.length : gateDefinitions.length,
    gates_run: results.length,
    gates_failed: 0,
    results,
  };
}
