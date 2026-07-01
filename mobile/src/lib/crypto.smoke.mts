import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import { after, afterEach, beforeEach, test } from 'node:test';
import {
  createJournalCryptoKeyHandle,
  decryptJournalData,
  deriveIsolationKey,
  disposeJournalCryptoKey,
  encryptJournalData,
  getJournalCryptoKey,
  getJournalCryptoProviderStatus,
  journalAssociatedData,
  JOURNAL_PBKDF2_ITERATIONS,
  runJournalCryptoSelfTest,
} from './crypto.ts';

const originalCrypto = globalThis.crypto;
const originalNativeRequired = process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO;
const mobileCryptoSmokeProofMarkers = [
  'mobile_crypto_aes_gcm=true',
  'mobile_crypto_associated_data=true',
  'mobile_crypto_associated_data_input_guard=true',
  'mobile_crypto_unique_iv=true',
  'mobile_crypto_runtime_buffer_zeroization=true',
  'mobile_crypto_native_required_fail_closed=true',
  'mobile_crypto_native_required_self_test_fail_closed=true',
  'mobile_crypto_self_test_markers=true',
  'mobile_crypto_revoked_key_rejected=true',
];

function bufferFromText(value: string): ArrayBuffer {
  const bytes = new TextEncoder().encode(value);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function captureBuffer(value: BufferSource | undefined): Uint8Array | null {
  if (!value) return null;
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value);
}

function assertZeroized(name: string, bytes: Uint8Array | null): void {
  assert.ok(bytes, `${name} buffer was not captured`);
  assert.ok(bytes.every(value => value === 0), `${name} buffer was not zeroized`);
}

beforeEach(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: webcrypto,
  });
  delete process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO;
});

afterEach(() => {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: originalCrypto,
  });
  if (originalNativeRequired === undefined) {
    delete process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO;
  } else {
    process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = originalNativeRequired;
  }
});

test('journal AES-GCM encrypts, decrypts, and rejects tampered ciphertext', async () => {
  const plaintext = 'Private journal note for mobile AES-GCM smoke coverage.';
  const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
  const associatedData = journalAssociatedData('journal:v1:server-derived-salt', 1);
  const encrypted = await encryptJournalData(plaintext, key, associatedData);
  const secondEncrypted = await encryptJournalData(plaintext, key, associatedData);

  assert.notEqual(encrypted.ciphertext, Buffer.from(plaintext).toString('base64'));
  assert.ok(encrypted.iv.length > 0);
  assert.notEqual(secondEncrypted.iv, encrypted.iv, 'AES-GCM IVs must be unique per encryption');
  assert.notEqual(secondEncrypted.ciphertext, encrypted.ciphertext, 'same journal plaintext must not produce repeated ciphertext');
  assert.equal(await decryptJournalData(encrypted, key, associatedData), plaintext);

  await assert.rejects(
    () => decryptJournalData({ ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -2)}AA` }, key, associatedData),
    /decrypt|operation|data|authentication/i,
  );
  await assert.rejects(
    () => decryptJournalData(encrypted, key, journalAssociatedData('journal:v1:different-salt', 1)),
    /decrypt|operation|data|authentication/i,
    'wrong associated data must reject journal ciphertext',
  );
});

test('journal associated data rejects missing salt identity', () => {
  assert.throws(
    () => journalAssociatedData('   ', 1),
    /server salt identifier/i,
  );
  assert.throws(
    () => journalAssociatedData('journal:v1:server-derived-salt', 0),
    /positive integer salt version/i,
  );
  assert.throws(
    () => journalAssociatedData('journal:v1:server-derived-salt', 1.5),
    /positive integer salt version/i,
  );
});

test('local smoke reports WebCrypto fallback as non-production provider', () => {
  assert.deepEqual(getJournalCryptoProviderStatus(), {
    provider: 'webcrypto-fallback',
    nativeRequired: false,
  });
});

test('journal key derivation uses architecture PBKDF2 work factor', () => {
  assert.equal(JOURNAL_PBKDF2_ITERATIONS, 600000);
});

test('journal key derivation rejects blank passphrase or server salt', async () => {
  await assert.rejects(
    () => deriveIsolationKey('   ', 'journal:v1:server-derived-salt'),
    /passphrase is required/i,
  );
  await assert.rejects(
    () => deriveIsolationKey('correct horse battery staple', '   '),
    /server salt material is required/i,
  );
});

test('journal keys are non-extractable and disposed handles cannot encrypt', async () => {
  const plaintext = 'Private journal note should not encrypt after key disposal.';
  const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
  await assert.rejects(() => webcrypto.subtle.exportKey('raw', key as CryptoKey));

  const handle = createJournalCryptoKeyHandle(key);
  assert.equal(getJournalCryptoKey(handle), key);

  disposeJournalCryptoKey(handle);
  assert.equal(handle.disposed, true);
  assert.equal(handle.key, null);
  assert.throws(() => getJournalCryptoKey(handle), /disposed/);
  await assert.rejects(
    async () => encryptJournalData(plaintext, getJournalCryptoKey(handle)),
    /disposed/,
  );
  await assert.rejects(
    () => encryptJournalData('stale mobile key reference after disposal', key),
    /disposed/,
    'disposing a handle must revoke stale raw key references',
  );
});

test('journal encryption rejects keys not derived by the journal crypto module', async () => {
  const importedKey = await webcrypto.subtle.importKey(
    'raw',
    webcrypto.getRandomValues(new Uint8Array(32)),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );

  await assert.rejects(
    () => encryptJournalData('untracked mobile key plaintext', importedKey),
    /not derived by client-side journal key derivation/,
  );
});

test('mobile crypto zeroizes provider input buffers after operations', async () => {
  const syntheticKeyMaterial = {} as CryptoKey;
  const syntheticKey = {} as CryptoKey;
  const captured = {
    passphrase: null as Uint8Array | null,
    salt: null as Uint8Array | null,
    plaintext: null as Uint8Array | null,
    encryptIV: null as Uint8Array | null,
    encryptAssociatedData: null as Uint8Array | null,
    ciphertext: null as Uint8Array | null,
    decryptIV: null as Uint8Array | null,
    decryptAssociatedData: null as Uint8Array | null,
    decryptedPlaintext: null as Uint8Array | null,
  };
  const instrumentedCrypto = {
    getRandomValues: <T extends ArrayBufferView | null>(array: T): T => {
      if (array instanceof Uint8Array) {
        array.fill(9);
      }
      return array;
    },
    subtle: {
      importKey: async (
        _format: KeyFormat,
        keyData: BufferSource,
        _algorithm: AlgorithmIdentifier,
        _extractable: boolean,
        _keyUsages: KeyUsage[],
      ): Promise<CryptoKey> => {
        captured.passphrase = captureBuffer(keyData);
        return syntheticKeyMaterial;
      },
      deriveKey: async (
        algorithm: Pbkdf2Params,
        _baseKey: CryptoKey,
        _derivedKeyAlgorithm: AlgorithmIdentifier,
        _extractable: boolean,
        _keyUsages: KeyUsage[],
      ): Promise<CryptoKey> => {
        captured.salt = captureBuffer(algorithm.salt);
        return syntheticKey;
      },
      encrypt: async (
        algorithm: AesGcmParams,
        _key: CryptoKey,
        data: BufferSource,
      ): Promise<ArrayBuffer> => {
        captured.plaintext = captureBuffer(data);
        captured.encryptIV = captureBuffer(algorithm.iv);
        captured.encryptAssociatedData = captureBuffer(algorithm.additionalData);
        return bufferFromText('ciphertext');
      },
      decrypt: async (
        algorithm: AesGcmParams,
        _key: CryptoKey,
        data: BufferSource,
      ): Promise<ArrayBuffer> => {
        captured.ciphertext = captureBuffer(data);
        captured.decryptIV = captureBuffer(algorithm.iv);
        captured.decryptAssociatedData = captureBuffer(algorithm.additionalData);
        captured.decryptedPlaintext = new TextEncoder().encode('plaintext from provider');
        return captured.decryptedPlaintext.buffer as ArrayBuffer;
      },
    } as unknown as SubtleCrypto,
  } as unknown as Crypto;

  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: instrumentedCrypto,
  });

  const key = await deriveIsolationKey('zeroize-passphrase', 'journal:v1:zeroize-salt');
  assertZeroized('passphrase', captured.passphrase);
  assertZeroized('salt', captured.salt);

  const associatedData = journalAssociatedData('journal:v1:zeroize-salt', 1);
  const encrypted = await encryptJournalData('zeroize plaintext', key, associatedData);
  assertZeroized('plaintext', captured.plaintext);
  assertZeroized('encrypt IV', captured.encryptIV);
  assertZeroized('encrypt associated data', captured.encryptAssociatedData);

  const decrypted = await decryptJournalData(encrypted, key, associatedData);
  assert.equal(decrypted, 'plaintext from provider');
  assertZeroized('ciphertext', captured.ciphertext);
  assertZeroized('decrypt IV', captured.decryptIV);
  assertZeroized('decrypt associated data', captured.decryptAssociatedData);
  assertZeroized('decrypted plaintext', captured.decryptedPlaintext);
});

test('production native-required mode fails closed without native quick crypto', async () => {
  const fallbackKey = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
  process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = 'true';

  assert.deepEqual(getJournalCryptoProviderStatus(), {
    provider: 'unavailable',
    nativeRequired: true,
  });
  await assert.rejects(
    () => deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt'),
    /Native secure journal crypto provider unavailable/,
  );
  await assert.rejects(
    () => encryptJournalData('must not encrypt with fallback key in native-required mode', fallbackKey),
    /required native provider/,
  );
  await assert.rejects(
    () => runJournalCryptoSelfTest(),
    /requires the native react-native-quick-crypto provider/,
    'native-required self-test must fail closed when only WebCrypto fallback is available',
  );
});

test('journal crypto self-test emits native-device evidence markers', async () => {
  const result = await runJournalCryptoSelfTest();

  assert.equal(result.provider, 'webcrypto-fallback');
  assert.equal(result.nativeRequired, false);
  assert.deepEqual(result.markers, [
    'runJournalCryptoSelfTest',
    'provider=webcrypto-fallback',
    'native_required=false',
    'provider status webcrypto-fallback',
    'native-required false',
    'AES-GCM',
    'passphrase wiped',
    'passphrase buffer zeroized',
    'salt wiped',
    'salt buffer zeroized',
    'plaintext cleared',
    'plaintext buffer zeroized',
    'non-extractable',
    'aes_gcm_roundtrip=true',
    'round-trip',
    'unique_iv=true',
    'unique IV',
    'tamper_rejected=true',
    'tamper rejected',
    'associated_data_rejected=true',
    'associated data',
    'wrong associated data rejected',
    'associated_data_salt_id=journal:self-test:server-derived-salt',
    'associated_data_salt_version=1',
    'key_disposal=true',
    'key disposed',
    'disposed handle rejected',
    'revoked_key_rejected=true',
    'stale raw key rejected',
  ]);
});

after(() => {
  console.log(`mobile crypto smoke proof: ${mobileCryptoSmokeProofMarkers.join(', ')}`);
});
