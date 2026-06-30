import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { validateCIEvidenceGateMarkers } from './validate-ci-evidence-gates.mjs';
import { gateDefinitions } from './run-local-gates.mjs';
import { ciReleaseEvidenceProofMarkers } from './write-ci-release-evidence.mjs';

test('validateCIEvidenceGateMarkers accepts current ciprobe gate markers', async () => {
  const source = await readFile('tools/ciprobe/main.go', 'utf8');
  assert.deepEqual(validateCIEvidenceGateMarkers(source), {
    requiredGateCount: gateDefinitions.length + 1,
    requiredProofMarkerCount: ciReleaseEvidenceProofMarkers.length + 1,
  });
});

test('validateCIEvidenceGateMarkers explicitly requires strict staging PATH gate evidence', async () => {
  const source = await readFile('tools/ciprobe/main.go', 'utf8');
  const broken = source.replace('\t\t"gate: strict-staging-path-readiness",\n', '');
  assert.notEqual(broken, source, 'test fixture must remove the strict staging PATH gate marker');
  assert.throws(
    () => validateCIEvidenceGateMarkers(broken),
    /strict-staging-path-readiness/,
  );
});

test('validateCIEvidenceGateMarkers rejects missing local gate markers', async () => {
  const source = await readFile('tools/ciprobe/main.go', 'utf8');
  const broken = source.replace('\t\t"gate: rls-schema-validation",\n', '');
  assert.notEqual(broken, source, 'test fixture must remove the RLS schema gate marker');
  assert.throws(
    () => validateCIEvidenceGateMarkers(broken),
    /ciprobe required gate markers must mirror run-local-gates/,
  );
});

test('validateCIEvidenceGateMarkers rejects duplicate ciprobe markers', async () => {
  const source = await readFile('tools/ciprobe/main.go', 'utf8');
  const broken = source.replace(
    '\t\t"gate: rls-schema-validation",\n',
    '\t\t"gate: rls-schema-validation",\n\t\t"gate: rls-schema-validation",\n',
  );
  assert.notEqual(broken, source, 'test fixture must duplicate the RLS schema gate marker');
  assert.throws(
    () => validateCIEvidenceGateMarkers(broken),
    /duplicate or extra entries/,
  );
});

test('validateCIEvidenceGateMarkers rejects missing proof markers', async () => {
  const source = await readFile('tools/ciprobe/main.go', 'utf8');
  const broken = source.replace('\t\t"local_gate_markers_included=true",\n', '');
  assert.notEqual(broken, source, 'test fixture must remove a release evidence proof marker');
  assert.throws(
    () => validateCIEvidenceGateMarkers(broken),
    /ciprobe required proof markers must mirror write-ci-release-evidence proof markers/,
  );
});

test('validateCIEvidenceGateMarkers rejects duplicate proof markers', async () => {
  const source = await readFile('tools/ciprobe/main.go', 'utf8');
  const broken = source.replace(
    '\t\t"local_gate_markers_included=true",\n',
    '\t\t"local_gate_markers_included=true",\n\t\t"local_gate_markers_included=true",\n',
  );
  assert.notEqual(broken, source, 'test fixture must duplicate a release evidence proof marker');
  assert.throws(
    () => validateCIEvidenceGateMarkers(broken),
    /ciprobe required proof markers must not contain duplicate or extra entries/,
  );
});
