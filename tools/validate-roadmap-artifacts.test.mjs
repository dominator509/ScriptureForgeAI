import assert from 'node:assert/strict';
import test from 'node:test';
import { phaseSpecs, validateRoadmapArtifacts, validateRoadmapText } from './validate-roadmap-artifacts.mjs';

test('validateRoadmapArtifacts accepts all prescribed phase artifacts', async () => {
  const result = await validateRoadmapArtifacts();
  assert.equal(result.phase_count, 6);
  assert.deepEqual(result.files, phaseSpecs.map((spec) => spec.file));
});

test('validateRoadmapText rejects a phase artifact without external status', () => {
  const spec = phaseSpecs[0];
  const text = [
    '# Phase 01: Infrastructure & Data Core',
    'Source: `SF-roadmap.md`',
    '## Scope',
    '## Task Matrix',
    '## Acceptance Evidence',
    '## External Blockers',
    'Local implementation: tracked and gated.',
  ].join('\n');
  assert.throws(() => validateRoadmapText(text, spec), /external evidence status/);
});
