import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export const requiredMarkers = [
  { id: 'go-setup', text: "go-version: '1.24.3'" },
  { id: 'codex-branch-push', text: '"codex/**"' },
  { id: 'postgres-service', text: 'pgvector/pgvector:pg16' },
  { id: 'go-fuzz', text: 'go test -fuzz=FuzzSanitizeInput' },
  { id: 'go-test', text: 'go test ./...' },
  { id: 'postgres-schema', text: 'Apply Postgres Integration Schema' },
  { id: 'rls-integration', text: 'go test ./tests/integration ./internal/ports -count=1 -timeout=90s -v' },
  { id: 'http-load-smoke', text: 'go run ./tools/loadtest -self-test' },
  { id: 'websocket-load-smoke', text: 'go run ./tools/loadtest -websocket-self-test' },
  { id: 'evidence-probes', text: 'go test ./tools/ciprobe ./tools/stagingprobe ./tools/tenantprobe' },
  { id: 'observability-validation', text: 'node tools/validate-observability.mjs' },
  { id: 'secret-hygiene', text: 'node tools/validate-secret-hygiene.mjs' },
  { id: 'deployment-skeleton', text: 'node tools/validate-deployment-skeleton.mjs' },
  { id: 'staging-evidence', text: 'node tools/validate-staging-evidence.mjs' },
  { id: 'staging-evidence-tests', text: 'node --test tools/validate-staging-evidence.test.mjs' },
  { id: 'readiness-claim-tests', text: 'node --test tools/verify-production-readiness.test.mjs' },
  { id: 'evidence-recorder-tests', text: 'node --test tools/record-staging-evidence.test.mjs' },
  { id: 'evidence-bootstrap-tests', text: 'node --test tools/bootstrap-staging-evidence.test.mjs' },
  { id: 'evidence-gap-report-tests', text: 'node --test tools/report-staging-evidence-gaps.test.mjs' },
  { id: 'ci-release-evidence-tests', text: 'node --test tools/write-ci-release-evidence.test.mjs' },
  { id: 'local-gate-runner-tests', text: 'node --test tools/run-local-gates.test.mjs tools/validate-local-gate-report.test.mjs' },
  { id: 'security-artifacts', text: 'node tools/validate-security-artifacts.mjs' },
  { id: 'dependency-risk', text: 'node tools/validate-dependency-risk.mjs' },
  { id: 'dependency-risk-tests', text: 'node --test tools/validate-dependency-risk.test.mjs' },
  { id: 'go-vet', text: 'go vet ./...' },
  { id: 'web-npm-ci', text: 'working-directory: web' },
  { id: 'web-audit', text: 'npm audit --audit-level=moderate' },
  { id: 'web-smoke', text: 'npm run smoke' },
  { id: 'web-typecheck', text: 'npm run typecheck' },
  { id: 'web-build', text: 'npm run build' },
  { id: 'mobile-npm-ci', text: 'working-directory: mobile' },
  { id: 'mobile-audit', text: 'npm audit --audit-level=high' },
  { id: 'mobile-smoke', text: 'npm run smoke' },
  { id: 'mobile-build-check', text: 'npm run build:check' },
  { id: 'rust-protobuf-validation', text: 'node tools/verify-rust-protobuf.mjs' },
  { id: 'rust-cargo-test', text: 'cargo test' },
  { id: 'terraform-fmt', text: 'terraform fmt -check' },
  { id: 'terraform-validate', text: 'terraform validate' },
  { id: 'trufflehog', text: 'trufflesecurity/trufflehog' },
  { id: 'ci-evidence-write', text: 'node tools/write-ci-release-evidence.mjs --output artifacts/ci-release-evidence.txt' },
  { id: 'ci-evidence-validate', text: 'go run ./tools/ciprobe -run-artifact-file artifacts/ci-release-evidence.txt -commit-sha "$GITHUB_SHA"' },
  { id: 'ci-evidence-upload', text: 'actions/upload-artifact@v4' },
];

export function validateCIWorkflow(text) {
  const missing = requiredMarkers.filter((marker) => !text.includes(marker.text));
  assert.equal(missing.length, 0, `security workflow missing required gates: ${missing.map((marker) => marker.id).join(', ')}`);
  assert.ok(text.includes('name: Security Pipeline Verification'), 'security workflow name is required');
  assert.ok(text.includes('runs-on: ubuntu-latest'), 'security workflow must run on ubuntu-latest');
  return {
    markerCount: requiredMarkers.length,
  };
}

async function main() {
  const workflowPath = process.argv[2] ?? '.github/workflows/security.yml';
  const text = await readFile(workflowPath, 'utf8');
  const result = validateCIWorkflow(text);
  console.log(`CI workflow validated: ${workflowPath} (${result.markerCount} required markers)`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-ci-workflow.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
