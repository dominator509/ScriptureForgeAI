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
  const broken = text.replace('go vet ./...', 'echo skipped-go-vet');
  assert.throws(
    () => validateCIWorkflow(broken),
    /go-vet/,
  );
});

test('validateCIWorkflow rejects missing release evidence upload', async () => {
  const text = await readFile('.github/workflows/security.yml', 'utf8');
  const broken = text.replace('actions/upload-artifact@v4', 'actions/download-artifact@v4');
  assert.throws(
    () => validateCIWorkflow(broken),
    /ci-evidence-upload/,
  );
});
