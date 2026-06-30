import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { journalCryptoProofMarkers } from './verify-journal-crypto.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('journal crypto verifier emits every local proof marker', () => {
  const result = spawnSync(process.execPath, ['tools/verify-journal-crypto.mjs'], {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: '',
    },
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /journal crypto verification passed:/);
  for (const marker of journalCryptoProofMarkers) {
    assert.ok(result.stdout.includes(marker), `verifier output missing ${marker}`);
  }
});

test('journal crypto proof markers cover native provider binding and harness checks', () => {
  assert.deepEqual(
    [
      'native_quick_crypto=true',
      'native_provider_bound_keys=true',
      'native_provider_harness=true',
      'native_required_fail_closed=true',
      'mobile_staging_native_required=true',
    ],
    journalCryptoProofMarkers.slice(0, 5),
  );
  assert.ok(journalCryptoProofMarkers.includes('blank_key_input_rejected=true'));
  assert.ok(journalCryptoProofMarkers.includes('associated_data_salt_binding=true'));
  assert.ok(journalCryptoProofMarkers.includes('runtime_buffer_zeroization=true'));
  assert.ok(journalCryptoProofMarkers.includes('native_device_self_test_export=true'));
  assert.ok(journalCryptoProofMarkers.includes('native_device_self_test_markers=true'));
  assert.ok(journalCryptoProofMarkers.includes('native_required_self_test_fail_closed=true'));
  assert.equal(new Set(journalCryptoProofMarkers).size, journalCryptoProofMarkers.length);
});
