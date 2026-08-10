import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { requiredMarkers, validateCIWorkflow } from './validate-ci-workflow.mjs';

test('validateCIWorkflow accepts the repository security workflow', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const result = validateCIWorkflow(text);
  assert.equal(result.markerCount, requiredMarkers.length);
});

test('validateCIWorkflow rejects missing required gates', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('node tools/run-go-core-gate.mjs --mode vet --bin go', 'echo skipped-go-vet');
  assert.notEqual(broken, text, 'fixture workflow must include wrapped go vet gate');
  assert.throws(
    () => validateCIWorkflow(broken),
    /go-vet/,
  );
});

test('validateCIWorkflow rejects missing release evidence upload', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('actions/upload-artifact@', 'actions/download-artifact@');
  assert.throws(
    () => validateCIWorkflow(broken),
    /ci-evidence-upload/,
  );
});

test('validateCIWorkflow rejects mutable action references', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', 'actions/checkout@v4');
  assert.throws(
    () => validateCIWorkflow(broken),
    /pinned to commit SHAs/,
  );
});

test('validateCIWorkflow rejects legacy Node20 action majors', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1 (node24)', 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4 (node20)');
  assert.throws(
    () => validateCIWorkflow(broken),
    /must use the current node24 action major/,
  );
});

test('validateCIWorkflow rejects skip-tolerant RLS integration configuration', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('        REQUIRE_DATABASE_URL: "true"\n', '');
  assert.throws(
    () => validateCIWorkflow(broken),
    /rls-integration-requires-db/,
  );
});

test('validateCIWorkflow rejects raw RLS go test without semantic proof wrapper', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('node tools/run-rls-db-integration.mjs --bin go', 'go test ./tests/integration ./internal/ports -count=1 -timeout=90s -v');
  assert.notEqual(broken, text, 'fixture workflow must include semantic RLS wrapper');
  assert.throws(
    () => validateCIWorkflow(broken),
    /rls-integration/,
  );
});

test('validateCIWorkflow rejects missing CI PATH readiness validation', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(
    '    - name: Validate CI Project PATH Readiness\n      run: node tools/verify-project-path.mjs --ci\n\n',
    '',
  );
  assert.notEqual(broken, text, 'fixture workflow must include standalone CI PATH readiness validation');
  assert.throws(
    () => validateCIWorkflow(broken),
    /ci-path-readiness/,
  );
});

test('validateCIWorkflow rejects missing strict staging PATH readiness validation', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('node tools/verify-project-path.mjs --ci --strict-staging', 'node tools/verify-project-path.mjs --ci');
  assert.notEqual(broken, text, 'fixture workflow must include strict staging PATH readiness validation');
  assert.throws(
    () => validateCIWorkflow(broken),
    /strict-staging-path-readiness/,
  );
});

test('validateCIWorkflow rejects missing staging evidence PATH tool installation', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const missingGopls = text.replace('go install golang.org/x/tools/gopls@v0.20.0', 'go version');
  assert.throws(
    () => validateCIWorkflow(missingGopls),
    /ci-gopls-install/,
  );

  const missingGoBinPath = text.replace('echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"', 'go env GOPATH');
  assert.throws(
    () => validateCIWorkflow(missingGoBinPath),
    /ci-go-bin-path/,
  );

  const missingKubectl = text.replace('https://dl.k8s.io/release/v1.34.1/bin/linux/amd64/kubectl', 'https://example.invalid/kubectl');
  assert.throws(
    () => validateCIWorkflow(missingKubectl),
    /ci-kubectl-install/,
  );

  const missingAWSDownload = text.replace('https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.27.41.zip', 'https://example.invalid/awscli.zip');
  assert.throws(
    () => validateCIWorkflow(missingAWSDownload),
    /ci-awscli-v2-download/,
  );

  const missingAWSInstall = text.replace('sudo ./aws/install --update', 'aws --version');
  assert.throws(
    () => validateCIWorkflow(missingAWSInstall),
    /ci-awscli-v2-install/,
  );

  const missingUnzip = text.replace('sudo apt-get install -y postgresql-client unzip', 'sudo apt-get install -y postgresql-client');
  assert.throws(
    () => validateCIWorkflow(missingUnzip),
    /ci-postgres-unzip-install/,
  );
});

test('validateCIWorkflow rejects incomplete local tooling test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/run-rls-db-integration-docker.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include Docker RLS tooling test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing Serena/Obsidian validator test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/validate-serena-obsidian.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include Serena/Obsidian validator tests');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing npm audit wrapper test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/run-npm-audit.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include npm audit wrapper test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing Terraform init wrapper test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/run-terraform-init.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include Terraform init wrapper test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing Terraform command wrapper test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/run-terraform-command.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include Terraform command wrapper test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing client command wrapper test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/run-client-command.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include client command wrapper test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing journal crypto verifier test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/verify-journal-crypto.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include journal crypto verifier test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects raw Go test and vet gates without proof wrappers', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');

  const rawGoTest = text.replace(
    'node tools/run-go-core-gate.mjs --mode test --bin go',
    'GO_ENV=testing CI=true go test ./...',
  );
  assert.notEqual(rawGoTest, text, 'fixture workflow must include wrapped Go test gate');
  assert.throws(
    () => validateCIWorkflow(rawGoTest),
    /go-test/,
  );

  const rawGoVet = text.replace(
    'node tools/run-go-core-gate.mjs --mode vet --bin go',
    'go vet ./...',
  );
  assert.notEqual(rawGoVet, text, 'fixture workflow must include wrapped Go vet gate');
  assert.throws(
    () => validateCIWorkflow(rawGoVet),
    /go-vet/,
  );
});

test('validateCIWorkflow rejects missing Go core gate wrapper test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/run-go-core-gate.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include Go core gate wrapper test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects raw production evidence probe tests without proof wrapper', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(
    'node tools/run-go-probe-tests.mjs --bin go',
    'go test ./tools/ciprobe ./tools/stagingprobe ./tools/tenantprobe ./tools/rustprobe ./tools/observabilityprobe ./tools/securityprobe ./tools/resilienceprobe ./tools/mobileprobe ./tools/deploymentprobe ./tools/abuseprobe ./tools/zoomprobe ./tools/aiprobe ./tools/loadtest -count=1',
  );
  assert.notEqual(broken, text, 'fixture workflow must include wrapped production evidence probe tests');
  assert.throws(
    () => validateCIWorkflow(broken),
    /evidence-probes/,
  );
});

test('validateCIWorkflow rejects missing production evidence probe wrapper test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/run-go-probe-tests.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include production evidence probe wrapper test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects raw client build/typecheck gates without proof wrappers', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');

  const rawWebTypecheck = text.replace(
    'node ../tools/run-client-command.mjs --cwd . --script typecheck --proof-name web-typecheck-gate --marker web_typescript_no_emit=true --marker web_runtime_types=true --bin npm',
    'npm run typecheck',
  );
  assert.notEqual(rawWebTypecheck, text, 'fixture workflow must include wrapped web typecheck');
  assert.throws(
    () => validateCIWorkflow(rawWebTypecheck),
    /web-typecheck/,
  );

  const rawWebBuild = text.replace(
    'node ../tools/run-client-command.mjs --cwd . --script build --proof-name web-build-gate --marker next_build=true --marker web_production_bundle=true --bin npm',
    'npm run build',
  );
  assert.notEqual(rawWebBuild, text, 'fixture workflow must include wrapped web build');
  assert.throws(
    () => validateCIWorkflow(rawWebBuild),
    /web-build/,
  );

  const rawMobileBuildCheck = text.replace(
    'node ../tools/run-client-command.mjs --cwd . --script build:check --proof-name mobile-build-check-gate --marker mobile_typecheck=true --marker mobile_smoke=true --marker mobile_crypto_verification=true --require-output "journal crypto verification passed:" --bin npm',
    'npm run build:check',
  );
  assert.notEqual(rawMobileBuildCheck, text, 'fixture workflow must include wrapped mobile build check');
  assert.throws(
    () => validateCIWorkflow(rawMobileBuildCheck),
    /mobile-build-check/,
  );
});

test('validateCIWorkflow rejects missing security artifact validator test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/validate-security-artifacts.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include security artifact validator test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing observability validator test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(' tools/validate-observability.test.mjs', '');
  assert.notEqual(broken, text, 'fixture workflow must include observability validator test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing secret hygiene validator test coverage', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const missingStandalone = text.replace(
    '    - name: Test Secret Hygiene Validator\n      run: node --test tools/validate-secret-hygiene.test.mjs\n\n',
    '',
  );
  assert.notEqual(missingStandalone, text, 'fixture workflow must include standalone secret hygiene validator test');
  assert.throws(
    () => validateCIWorkflow(missingStandalone),
    /secret-hygiene-tests/,
  );

  const missingTooling = text.replace(
    ' tools/validate-secret-hygiene.test.mjs tools/validate-staging-evidence.test.mjs',
    ' tools/validate-staging-evidence.test.mjs',
  );
  assert.notEqual(missingTooling, text, 'fixture workflow must include secret hygiene validator in local tooling tests');
  assert.throws(
    () => validateCIWorkflow(missingTooling),
    /local-tooling-tests/,
  );
});

test('validateCIWorkflow rejects missing staging evidence contract sync check', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(
    'node tools/sync-staging-evidence-contract.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --check',
    'node tools/sync-staging-evidence-contract.mjs --check',
  );
  assert.notEqual(broken, text, 'fixture workflow must include staging evidence contract sync check');
  assert.throws(
    () => validateCIWorkflow(broken),
    /staging-evidence-contract-check/,
  );
});

test('validateCIWorkflow rejects implicit Obsidian readiness snapshot inputs', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(
    'node tools/sync-obsidian-readiness.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --expected-release-candidate replace-with-git-sha-or-tag --check',
    'node tools/sync-obsidian-readiness.mjs --check',
  );
  assert.notEqual(broken, text, 'fixture workflow must include explicit Obsidian readiness snapshot inputs');
  assert.throws(
    () => validateCIWorkflow(broken),
    /obsidian-readiness-snapshot-check/,
  );
});

test('validateCIWorkflow rejects missing staging evidence gap report gate', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(
    'node tools/report-staging-evidence-gaps.mjs --manifest production-readiness/staging-evidence.example.json --contract-manifest production-readiness/staging-evidence.example.json --allow-blockers',
    'node tools/report-staging-evidence-gaps.mjs --manifest production-readiness/staging-evidence.example.json',
  );
  assert.notEqual(broken, text, 'fixture workflow must include staging evidence gap report check');
  assert.throws(
    () => validateCIWorkflow(broken),
    /staging-evidence-gap-report/,
  );
});

test('validateCIWorkflow rejects unlocked Rust cargo tests', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('node tools/run-rust-cargo-gate.mjs --bin cargo', 'cargo test');
  assert.throws(
    () => validateCIWorkflow(broken),
    /rust-cargo-test/,
  );
});

test('validateCIWorkflow rejects non-recursive Terraform formatting checks', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(
    'node tools/run-terraform-command.mjs --mode fmt --bin terraform',
    'terraform fmt -check',
  );
  assert.notEqual(broken, text, 'fixture workflow must include wrapped recursive Terraform fmt');
  assert.throws(
    () => validateCIWorkflow(broken),
    /terraform-fmt/,
  );
});

test('validateCIWorkflow rejects raw Terraform validate without proof wrapper', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace(
    'node tools/run-terraform-command.mjs --mode validate --bin terraform',
    'terraform validate',
  );
  assert.notEqual(broken, text, 'fixture workflow must include wrapped Terraform validate');
  assert.throws(
    () => validateCIWorkflow(broken),
    /terraform-validate/,
  );
});

test('validateCIWorkflow rejects release evidence written before clean source control proof', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const cleanMarker = '    - name: Verify Source Control Clean Before Release Evidence';
  const writeMarker = '    - name: Write CI Release Evidence';
  const cleanIndex = text.indexOf(cleanMarker);
  const writeIndex = text.indexOf(writeMarker);
  assert.ok(cleanIndex > -1 && writeIndex > cleanIndex, 'fixture workflow must write evidence after clean proof');

  const cleanBlockEnd = text.indexOf('\n    - name:', cleanIndex + cleanMarker.length);
  const writeBlockEnd = text.indexOf('\n    - name:', writeIndex + writeMarker.length);
  const cleanBlock = text.slice(cleanIndex, cleanBlockEnd);
  const writeBlock = text.slice(writeIndex, writeBlockEnd);
  const broken = text
    .slice(0, cleanIndex)
    + writeBlock
    + '\n'
    + cleanBlock
    + text.slice(cleanBlockEnd, writeIndex)
    + text.slice(writeBlockEnd);

  assert.throws(
    () => validateCIWorkflow(broken),
    /ci-evidence-write/,
  );
});

test('validateCIWorkflow rejects upload before release evidence validation', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const validateMarker = '    - name: Validate CI Release Evidence';
  const uploadMarker = '    - name: Upload CI Release Evidence';
  const validateIndex = text.indexOf(validateMarker);
  const uploadIndex = text.indexOf(uploadMarker);
  assert.ok(validateIndex > -1 && uploadIndex > validateIndex, 'fixture workflow must upload evidence after validation');

  const validateBlockEnd = text.indexOf('\n    - name:', validateIndex + validateMarker.length);
  const uploadBlock = text.slice(uploadIndex);
  const validateBlock = text.slice(validateIndex, validateBlockEnd);
  const broken = text.slice(0, validateIndex) + uploadBlock + '\n' + validateBlock;

  assert.throws(
    () => validateCIWorkflow(broken),
    /ci-evidence-upload/,
  );
});
