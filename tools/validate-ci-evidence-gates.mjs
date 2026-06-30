import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { gateDefinitions } from './run-local-gates.mjs';
import { ciReleaseEvidenceProofMarkers, requiredGates } from './write-ci-release-evidence.mjs';

export const ciEvidenceGateProofMarkers = [
  'run_local_gates_mirrored=true',
  'strict_staging_path_gate_mirrored=true',
  'write_ci_release_evidence_mirrored=true',
  'ciprobe_required_gate_markers_mirrored=true',
  'ciprobe_release_evidence_proof_markers_mirrored=true',
  'trufflehog_release_marker_required=true',
  'duplicate_gate_markers_rejected=true',
];

export function extractCiprobeRequiredGateMarkers(source) {
  const match = source.match(/func requiredGateMarkers\(\) \[\]string \{\s*return \[\]string\{([\s\S]*?)\n\s*\}\s*\n\}/);
  assert.ok(match, 'tools/ciprobe requiredGateMarkers function is required');
  return [...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]);
}

export function extractCiprobeRequiredProofMarkers(source) {
  const match = source.match(/func requiredProofMarkers\(\) \[\]string \{\s*return \[\]string\{([\s\S]*?)\n\s*\}\s*\n\}/);
  assert.ok(match, 'tools/ciprobe requiredProofMarkers function is required');
  return [...match[1].matchAll(/"([^"]+)"/g)].map((entry) => entry[1]);
}

export function validateCIEvidenceGateMarkers(ciprobeSource) {
  const expectedGateMarkers = gateDefinitions.map((gate) => `gate: ${gate.id}`);
  const expectedReleaseMarkers = [...expectedGateMarkers, 'TruffleHog Secret Scanning'];
  const expectedProofMarkers = ['proof markers:', ...ciReleaseEvidenceProofMarkers];
  const ciprobeMarkers = extractCiprobeRequiredGateMarkers(ciprobeSource);
  const ciprobeProofMarkers = extractCiprobeRequiredProofMarkers(ciprobeSource);
  const normalizedCiprobeMarkers = ciprobeMarkers.map((marker) => (marker === 'trufflehog' ? 'TruffleHog Secret Scanning' : marker));

  assert.deepEqual(
    new Set(requiredGates),
    new Set(expectedReleaseMarkers),
    'write-ci-release-evidence required gates must mirror run-local-gates plus TruffleHog',
  );
  assert.ok(
    expectedGateMarkers.includes('gate: strict-staging-path-readiness'),
    'run-local-gates must include strict-staging-path-readiness',
  );
  assert.ok(
    requiredGates.includes('gate: strict-staging-path-readiness'),
    'write-ci-release-evidence required gates must include strict-staging-path-readiness',
  );
  assert.ok(
    normalizedCiprobeMarkers.includes('gate: strict-staging-path-readiness'),
    'ciprobe required gate markers must include strict-staging-path-readiness',
  );
  assert.deepEqual(
    new Set(normalizedCiprobeMarkers),
    new Set(expectedReleaseMarkers),
    'ciprobe required gate markers must mirror run-local-gates plus TruffleHog',
  );
  assert.equal(
    normalizedCiprobeMarkers.length,
    expectedReleaseMarkers.length,
    'ciprobe required gate markers must not contain duplicate or extra entries',
  );
  assert.deepEqual(
    new Set(ciprobeProofMarkers),
    new Set(expectedProofMarkers),
    'ciprobe required proof markers must mirror write-ci-release-evidence proof markers',
  );
  assert.equal(
    ciprobeProofMarkers.length,
    expectedProofMarkers.length,
    'ciprobe required proof markers must not contain duplicate or extra entries',
  );

  return { requiredGateCount: expectedReleaseMarkers.length, requiredProofMarkerCount: expectedProofMarkers.length };
}

async function main() {
  const ciprobeSource = await readFile('tools/ciprobe/main.go', 'utf8');
  const result = validateCIEvidenceGateMarkers(ciprobeSource);
  console.log(`CI evidence gate markers validated across ${result.requiredGateCount} required entries and ${result.requiredProofMarkerCount} proof markers: ${ciEvidenceGateProofMarkers.join(', ')}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-ci-evidence-gates.mjs')) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
