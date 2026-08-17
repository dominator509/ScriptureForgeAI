import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export const ciWorkflowProofMarkers = [
  'go_1_24_3=true',
  'ci_path_readiness_gate=true',
  'strict_staging_path_readiness_gate=true',
  'rls_db_integration_required=true',
  'web_mobile_rust_terraform_gates=true',
  'security_scans_present=true',
  'local_tooling_tests_present=true',
  'roadmap_subroadmap_gate=true',
  'staging_evidence_contract_check=true',
  'staging_evidence_gap_report_check=true',
  'clean_git_before_release_evidence=true',
  'release_evidence_write_validate_upload_order=true',
  'node24_action_runtime=true',
];

export const requiredMarkers = [
  { id: 'go-setup', text: "go-version: '1.24.3'" },
  { id: 'codex-branch-push', text: '"codex/**"' },
  { id: 'postgres-service', text: 'pgvector/pgvector@sha256:eac621400b7b7ff52493883e41e930e3d104695fea5b68cc0c42370cf7880067' },
  { id: 'go-fuzz', text: 'go test -fuzz=FuzzSanitizeInput' },
  { id: 'go-test', text: 'node tools/run-go-core-gate.mjs --mode test --bin go' },
  { id: 'postgres-schema', text: 'Apply Postgres Integration Schema' },
  { id: 'ci-postgres-unzip-install', text: 'sudo apt-get install -y postgresql-client unzip' },
  { id: 'ci-go-bin-path', text: 'echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"' },
  { id: 'ci-awscli-v2-download', text: 'curl -fsSLo awscliv2.zip https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.27.41.zip' },
  { id: 'ci-awscli-v2-signature', text: 'awscli-exe-linux-x86_64-2.27.41.zip.sig' },
  { id: 'ci-awscli-v2-pgp', text: 'gpg --batch --verify awscliv2.zip.sig awscliv2.zip' },
  { id: 'ci-awscli-v2-fingerprint', text: 'FB5DB77FD5C118B80511ADA8A6310ACC4672475C' },
  { id: 'ci-awscli-v2-install', text: 'sudo ./aws/install --update' },
  { id: 'ci-gopls-install', text: 'go install golang.org/x/tools/gopls@2e31135b736b96cd609904370c71563ce5447826' },
  { id: 'ci-kubectl-install', text: 'curl -fsSLo kubectl https://dl.k8s.io/release/v1.34.1/bin/linux/amd64/kubectl' },
  { id: 'ci-kubectl-sha256', text: 'https://dl.k8s.io/release/v1.34.1/bin/linux/amd64/kubectl.sha256' },
  { id: 'ci-kubectl-checksum', text: 'sha256sum --check -' },
  { id: 'ci-path-readiness', text: 'Validate CI Project PATH Readiness' },
  { id: 'strict-staging-path-readiness', text: 'node tools/verify-project-path.mjs --ci --strict-staging' },
  { id: 'rls-integration', text: 'node tools/run-rls-db-integration.mjs --bin go' },
  { id: 'rls-integration-requires-db', text: 'REQUIRE_DATABASE_URL: "true"' },
  { id: 'http-load-smoke', text: 'go run ./tools/loadtest -self-test' },
  { id: 'websocket-load-smoke', text: 'go run ./tools/loadtest -websocket-self-test' },
  { id: 'evidence-probes', text: 'node tools/run-go-probe-tests.mjs --bin go' },
  { id: 'observability-validation', text: 'node tools/validate-observability.mjs' },
  { id: 'rls-schema-validation', text: 'node tools/validate-rls-schema.mjs' },
  { id: 'rls-schema-tests', text: 'node --test tools/validate-rls-schema.test.mjs' },
  { id: 'secret-hygiene', text: 'node tools/validate-secret-hygiene.mjs' },
  { id: 'secret-hygiene-tests', text: 'node --test tools/validate-secret-hygiene.test.mjs' },
  { id: 'deployment-skeleton', text: 'node tools/validate-deployment-skeleton.mjs' },
  { id: 'deployment-skeleton-tests', text: 'node --test tools/validate-deployment-skeleton.test.mjs' },
  { id: 'staging-evidence', text: 'node tools/validate-staging-evidence.mjs' },
  { id: 'staging-evidence-gap-report', text: 'node tools/report-staging-evidence-gaps.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --allow-blockers' },
  { id: 'staging-evidence-tests', text: 'node --test tools/validate-staging-evidence.test.mjs' },
  { id: 'readiness-claim-tests', text: 'node --test tools/verify-production-readiness.test.mjs' },
  { id: 'evidence-recorder-tests', text: 'node --test tools/record-staging-evidence.test.mjs' },
  { id: 'evidence-bootstrap-tests', text: 'node --test tools/bootstrap-staging-evidence.test.mjs' },
  { id: 'evidence-gap-report-tests', text: 'node --test tools/report-staging-evidence-gaps.test.mjs' },
  { id: 'ci-release-evidence-tests', text: 'node --test tools/write-ci-release-evidence.test.mjs' },
  { id: 'ci-evidence-gate-validation', text: 'node tools/validate-ci-evidence-gates.mjs' },
  { id: 'ci-evidence-gate-tests', text: 'node --test tools/validate-ci-evidence-gates.test.mjs' },
  { id: 'local-tooling-tests', text: 'node --test tools/run-local-gates.test.mjs tools/run-client-command.test.mjs tools/run-go-core-gate.test.mjs tools/run-rust-cargo-gate.test.mjs tools/run-go-probe-tests.test.mjs tools/run-npm-audit.test.mjs tools/run-terraform-command.test.mjs tools/run-terraform-init.test.mjs tools/run-rls-db-integration.test.mjs tools/run-rls-db-integration-docker.test.mjs tools/validate-local-gate-report.test.mjs tools/validate-ci-workflow.test.mjs tools/validate-ci-evidence-gates.test.mjs tools/validate-deployment-skeleton.test.mjs tools/validate-rls-schema.test.mjs tools/validate-observability.test.mjs tools/validate-dependency-risk.test.mjs tools/validate-security-artifacts.test.mjs tools/validate-secret-hygiene.test.mjs tools/validate-staging-evidence.test.mjs tools/verify-journal-crypto.test.mjs tools/verify-production-readiness.test.mjs tools/record-staging-evidence.test.mjs tools/bootstrap-staging-evidence.test.mjs tools/report-staging-evidence-gaps.test.mjs tools/sync-staging-evidence-contract.test.mjs tools/sync-obsidian-readiness.test.mjs tools/write-ci-release-evidence.test.mjs tools/verify-rust-protobuf.test.mjs tools/validate-serena-obsidian.test.mjs tools/verify-project-path.test.mjs tools/verify-mobile-image-size.test.mjs' },
  { id: 'security-artifacts', text: 'node tools/validate-security-artifacts.mjs' },
  { id: 'dependency-risk', text: 'node tools/validate-dependency-risk.mjs' },
  { id: 'dependency-risk-tests', text: 'node --test tools/validate-dependency-risk.test.mjs' },
  { id: 'go-vet', text: 'node tools/run-go-core-gate.mjs --mode vet --bin go' },
  { id: 'web-npm-ci', text: 'working-directory: web' },
  { id: 'web-audit', text: 'node ../tools/run-npm-audit.mjs --cwd . --level moderate --bin npm' },
  { id: 'web-smoke', text: 'npm run smoke' },
  { id: 'web-typecheck', text: 'node ../tools/run-client-command.mjs --cwd . --script typecheck --proof-name web-typecheck-gate --marker web_typescript_no_emit=true --marker web_runtime_types=true --bin npm' },
  { id: 'web-build', text: 'node ../tools/run-client-command.mjs --cwd . --script build --proof-name web-build-gate --marker next_build=true --marker web_production_bundle=true --bin npm' },
  { id: 'mobile-npm-ci', text: 'working-directory: mobile' },
  { id: 'mobile-audit', text: 'node ../tools/run-npm-audit.mjs --cwd . --level high --bin npm' },
  { id: 'mobile-smoke', text: 'npm run smoke' },
  { id: 'mobile-build-check', text: 'node ../tools/run-client-command.mjs --cwd . --script build:check --proof-name mobile-build-check-gate --marker mobile_typecheck=true --marker mobile_smoke=true --marker mobile_crypto_verification=true --require-output "journal crypto verification passed:" --bin npm' },
  { id: 'serena-obsidian-validation', text: 'node tools/validate-serena-obsidian.mjs' },
  { id: 'roadmap-artifacts', text: 'node tools/validate-roadmap-artifacts.mjs' },
  { id: 'roadmap-artifact-tests', text: 'node --test tools/validate-roadmap-artifacts.test.mjs' },
  { id: 'staging-evidence-contract-check', text: 'node tools/sync-staging-evidence-contract.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --check' },
  { id: 'obsidian-readiness-snapshot-check', text: 'node tools/sync-obsidian-readiness.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --expected-release-candidate replace-with-git-sha-or-tag --check' },
  { id: 'rust-protobuf-validation', text: 'node tools/verify-rust-protobuf.mjs' },
  { id: 'rust-cargo-test', text: 'node tools/run-rust-cargo-gate.mjs --bin cargo' },
  { id: 'terraform-fmt', text: 'node tools/run-terraform-command.mjs --mode fmt --bin terraform' },
  { id: 'terraform-init-wrapper', text: 'node tools/run-terraform-init.mjs --bin terraform --arg -chdir=build/terraform --arg init --arg -backend=false --arg -lockfile=readonly' },
  { id: 'terraform-validate', text: 'node tools/run-terraform-command.mjs --mode validate --bin terraform' },
  { id: 'trufflehog', text: 'trufflesecurity/trufflehog' },
  { id: 'ci-source-control-clean', text: 'Verify Source Control Clean Before Release Evidence' },
  { id: 'ci-source-control-diff', text: 'git diff --quiet' },
  { id: 'ci-source-control-cached-diff', text: 'git diff --cached --quiet' },
  { id: 'ci-source-control-untracked-status', text: 'git status --short' },
  { id: 'ci-evidence-write', text: 'node tools/write-ci-release-evidence.mjs --output artifacts/ci-release-evidence.txt' },
  { id: 'ci-evidence-validate', text: 'go run ./tools/ciprobe -run-artifact-file artifacts/ci-release-evidence.txt -commit-sha "$GITHUB_SHA"' },
  { id: 'ci-evidence-upload', text: 'actions/upload-artifact@' },
];

const orderedEvidenceStepMarkers = [
  { id: 'trufflehog', text: 'TruffleHog Secret Scanning' },
  { id: 'ci-source-control-clean', text: 'Verify Source Control Clean Before Release Evidence' },
  { id: 'ci-evidence-write', text: 'Write CI Release Evidence' },
  { id: 'ci-evidence-validate', text: 'Validate CI Release Evidence' },
  { id: 'ci-evidence-upload', text: 'Upload CI Release Evidence' },
];

export function validateCIWorkflow(text) {
  const missing = requiredMarkers.filter((marker) => !text.includes(marker.text));
  assert.equal(missing.length, 0, `security workflow missing required gates: ${missing.map((marker) => marker.id).join(', ')}`);
  assert.ok(text.includes('name: Security Pipeline Verification'), 'security workflow name is required');
  assert.ok(text.includes('runs-on: ubuntu-latest'), 'security workflow must run on ubuntu-latest');
  assert.match(text, /permissions:\s+contents:\s+read/, 'security workflow must declare read-only repository permissions');
  assert.ok(text.includes('persist-credentials: false'), 'checkout must not persist credentials for repository code execution');
  const mutableActionRefs = [...text.matchAll(/uses:\s*([^\s#]+)/g)]
    .map((match) => match[1])
    .filter((reference) => !/@[0-9a-f]{40}$/i.test(reference));
  assert.equal(mutableActionRefs.length, 0, `security workflow actions must be pinned to commit SHAs: ${mutableActionRefs.join(', ')}`);
  for (const [action, major] of [
    ['actions/checkout', 'v7'],
    ['actions/setup-go', 'v7'],
    ['actions/setup-node', 'v7'],
    ['hashicorp/setup-terraform', 'v4'],
    ['actions/upload-artifact', 'v7'],
  ]) {
    assert.match(text, new RegExp(`uses:\\s*${action.replace('/', '\\/')}@[0-9a-f]{40}\\s*#\\s*${major}\\.`, 'm'), `${action} must use the current node24 action major`);
  }
  let previousIndex = -1;
  for (const marker of orderedEvidenceStepMarkers) {
    const currentIndex = text.indexOf(marker.text);
    assert.ok(currentIndex > previousIndex, `security workflow release evidence order invalid near ${marker.id}`);
    previousIndex = currentIndex;
  }
  return {
    markerCount: requiredMarkers.length,
  };
}

async function main() {
  const workflowPath = process.argv[2] ?? '.github/workflows/security.yml';
  const text = await readFile(workflowPath, 'utf8');
  const result = validateCIWorkflow(text);
  console.log(`CI workflow validated: ${workflowPath} (${result.markerCount} required markers): ${ciWorkflowProofMarkers.join(', ')}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-ci-workflow.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
