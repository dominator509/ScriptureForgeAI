import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

export const requiredFiles = [
  'security/threat_model.md',
  'security/crypto_iam_audit.md',
  'security/sast_sca_report.md',
  'security/domain_specific_audit.md',
  'security/fuzzing_report.md',
  'security/secret_handling_review.md',
  'security/dependency_risk_register.md',
];

export const securityArtifactsProofMarkers = [
  'threat_model_stride=true',
  'crypto_iam_review=true',
  'sast_sca_report=true',
  'domain_specific_audit=true',
  'fuzzing_report=true',
  'secret_handling_review=true',
  'dependency_risk_register=true',
  'stale_security_claims_rejected=true',
  'residual_risk_signoff_path=true',
];

export const stalePhrases = [
  'No MFA currently enforced',
  'Terraform configurations located in `build/terraform/main.tf`',
  'All dependencies resolve to stable semantic versions without known active CVEs',
  'Two hardcoded connection strings discovered',
  'postgres://forge_admin_root:testpassword',
  'PlatformException',
  'future-incompatibility warning that should be addressed',
];

export const requiredCoverage = {
  'security/threat_model.md': [
    'Status last updated: 2026-06-25',
    'STRIDE Analysis',
    'Trust Boundaries',
    'Spoofing',
    'Tampering',
    'Repudiation',
    'Information Disclosure',
    'passphrase/salt byte wiping',
    'disposable journal key handles',
    'Denial of Service',
    'Elevation of Privilege',
    'Residual Risks Blocking Production Claim',
    'DRR-001',
  ],
  'security/crypto_iam_audit.md': [
    'Privileged roles require TOTP MFA',
    'Refresh tokens are opaque',
    'auth.SetTenantContext',
    'Journal plaintext and passphrases are client-side only',
    'wipes passphrase and salt byte buffers',
    'disposable handles',
    'IRSA',
    'Secrets Store CSI',
  ],
  'security/sast_sca_report.md': [
    'go vet ./...',
    'TruffleHog',
    'DRR-001',
    'sqlx-postgres 0.9.0',
    'build/terraform',
    'PodDisruptionBudgets',
    'Horizontal Pod Autoscalers',
    'backup retention',
    'named final snapshot',
    'rolling update strategy',
  ],
  'security/domain_specific_audit.md': [
    'Cross-organization data disclosure',
    'Plaintext leakage',
    'Citation-free or hallucinated AI responses',
    'Unauthorized access to live study rooms',
    'Meeting/webhook confusion',
  ],
  'security/fuzzing_report.md': [
    'FuzzSanitizeInput',
    'go test -fuzz=FuzzSanitizeInput',
    'RLS integration tests',
    'WebSocket tests',
    'Zoom tests',
  ],
  'security/secret_handling_review.md': [
    'tools/validate-secret-hygiene.mjs',
    'TruffleHog',
    'IRSA',
    'Secrets Store CSI',
    '`DATABASE_URL` uses a scoped application database user',
  ],
  'security/dependency_risk_register.md': [
    'DRR-001',
    'uuid <11.1.1',
    'expo@56.0.12, uuid@7.0.3',
    'Expo',
    'Risk decision',
    'Risk owner: Security/release owner',
    'Accepted by: Release owner and security reviewer',
    'Review due: 2026-07-25',
    'Expires: 2026-08-25',
    'Required closure',
  ],
};

export async function loadSecurityArtifactContents(files = requiredFiles) {
  const contents = new Map();
  for (const file of files) {
    contents.set(file, await readFile(file, 'utf8'));
  }
  return contents;
}

export function validateSecurityArtifactContents(contents, {
  staleClaimPhrases = stalePhrases,
  coverage = requiredCoverage,
} = {}) {
  const allSecurityText = [...contents.values()].join('\n');
  for (const phrase of staleClaimPhrases) {
    assert.ok(!allSecurityText.includes(phrase), `security artifacts contain stale phrase: ${phrase}`);
  }

  for (const [file, snippets] of Object.entries(coverage)) {
    const content = contents.get(file);
    assert.equal(typeof content, 'string', `${file} must be loaded for security artifact validation`);
    for (const snippet of snippets) {
      assert.ok(content.includes(snippet), `${file} missing ${snippet}`);
    }
  }

  return {
    proofMarkers: securityArtifactsProofMarkers,
  };
}

export async function validateSecurityArtifacts(files = requiredFiles) {
  return validateSecurityArtifactContents(await loadSecurityArtifactContents(files));
}

async function main() {
  const result = await validateSecurityArtifacts();
  console.log(`security artifacts validated: ${result.proofMarkers.join(', ')}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-security-artifacts.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
