import assert from 'node:assert/strict';
import test from 'node:test';
import {
  loadSecurityArtifactContents,
  requiredCoverage,
  requiredFiles,
  securityArtifactsProofMarkers,
  stalePhrases,
  validateSecurityArtifactContents,
  validateSecurityArtifacts,
} from './validate-security-artifacts.mjs';

test('validateSecurityArtifacts accepts current security documentation', async () => {
  const result = await validateSecurityArtifacts();

  assert.equal(result.proofMarkers, securityArtifactsProofMarkers);
  assert.ok(securityArtifactsProofMarkers.includes('stale_security_claims_rejected=true'));
  assert.ok(securityArtifactsProofMarkers.includes('residual_risk_signoff_path=true'));
});

test('validateSecurityArtifactContents rejects stale security claims', async () => {
  const contents = await loadSecurityArtifactContents();
  const targetFile = 'security/sast_sca_report.md';
  contents.set(targetFile, `${contents.get(targetFile)}\n${stalePhrases[0]}\n`);

  assert.throws(
    () => validateSecurityArtifactContents(contents),
    /stale phrase/,
  );
});

test('validateSecurityArtifactContents rejects missing required coverage markers', async () => {
  const contents = await loadSecurityArtifactContents();
  const targetFile = 'security/secret_handling_review.md';
  contents.set(
    targetFile,
    contents.get(targetFile).replace('`DATABASE_URL` uses a scoped application database user', '`DATABASE_URL` review removed'),
  );

  assert.throws(
    () => validateSecurityArtifactContents(contents),
    /scoped application database user/,
  );
});

test('validateSecurityArtifactContents rejects unloaded required files', async () => {
  const contents = await loadSecurityArtifactContents();
  contents.delete(requiredFiles[0]);

  assert.throws(
    () => validateSecurityArtifactContents(contents),
    /must be loaded/,
  );
});

test('required coverage includes each tracked security artifact', () => {
  for (const file of requiredFiles) {
    assert.ok(requiredCoverage[file]?.length > 0, `${file} should have required coverage markers`);
  }
});
