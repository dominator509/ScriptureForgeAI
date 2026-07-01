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
  journalAssociatedData,
  JOURNAL_PBKDF2_ITERATIONS,
} from './crypto.ts';

const originalWindow = globalThis.window;
const webCryptoSmokeProofMarkers = [
  'web_crypto_aes_gcm=true',
  'web_crypto_unique_iv=true',
  'web_crypto_associated_data=true',
  'web_crypto_associated_data_input_guard=true',
  'web_crypto_pbkdf2_600000=true',
  'web_crypto_key_disposal=true',
  'web_crypto_revoked_key_rejected=true',
];

beforeEach(() => {
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      crypto: webcrypto,
      atob: (value: string) => Buffer.from(value, 'base64').toString('binary'),
      btoa: (value: string) => Buffer.from(value, 'binary').toString('base64'),
    },
  });
});

afterEach(() => {
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: originalWindow,
  });
});

test('web journal AES-GCM round-trips and rejects tampered ciphertext', async () => {
  const plaintext = 'Private web journal note with pastoral context.';
  const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
  const associatedData = journalAssociatedData('journal:v1:server-derived-salt', 1);
  const encrypted = await encryptJournalData(plaintext, key, associatedData);
  const secondEncrypted = await encryptJournalData(plaintext, key, associatedData);

  assert.notEqual(encrypted.ciphertext, Buffer.from(plaintext).toString('base64'));
  assert.ok(encrypted.iv.length > 0);
  assert.notEqual(secondEncrypted.iv, encrypted.iv, 'AES-GCM IVs must be unique per encryption');
  assert.notEqual(
    secondEncrypted.ciphertext,
    encrypted.ciphertext,
    'same web journal plaintext must not produce repeated ciphertext',
  );
  assert.equal(await decryptJournalData(encrypted, key, associatedData), plaintext);

  await assert.rejects(
    () => decryptJournalData({ ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -2)}AA` }, key, associatedData),
    /decrypt|operation|data|authentication|payload/i,
  );
});

test('web journal AES-GCM rejects wrong associated data', async () => {
  const plaintext = 'Private web journal note bound to a salt context.';
  const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
  const associatedData = journalAssociatedData('journal:v1:server-derived-salt', 1);
  const encrypted = await encryptJournalData(plaintext, key, associatedData);

  await assert.rejects(
    () => decryptJournalData(encrypted, key, journalAssociatedData('journal:v1:different-salt', 1)),
    /decrypt|operation|data|authentication|payload/i,
    'wrong associated data must reject web journal ciphertext',
  );
});

test('web journal associated data rejects missing salt identity', () => {
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

test('web journal keys use architecture work factor and are non-extractable', async () => {
  assert.equal(JOURNAL_PBKDF2_ITERATIONS, 600000);
  const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');

  await assert.rejects(() => webcrypto.subtle.exportKey('raw', key));
});

test('web journal key derivation rejects blank passphrase or server salt', async () => {
  await assert.rejects(
    () => deriveIsolationKey('   ', 'journal:v1:server-derived-salt'),
    /passphrase is required/i,
  );
  await assert.rejects(
    () => deriveIsolationKey('correct horse battery staple', '   '),
    /server salt material is required/i,
  );
});

test('web journal key handles dispose active key references', async () => {
  const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
  const handle = createJournalCryptoKeyHandle(key);

  assert.equal(getJournalCryptoKey(handle), key);

  disposeJournalCryptoKey(handle);
  assert.equal(handle.disposed, true);
  assert.equal(handle.key, null);
  assert.throws(() => getJournalCryptoKey(handle), /disposed/);
  await assert.rejects(
    async () => encryptJournalData('disposed web journal plaintext', getJournalCryptoKey(handle)),
    /disposed/,
  );
  await assert.rejects(
    () => encryptJournalData('stale web key reference after disposal', key),
    /disposed/,
    'disposing a handle must revoke stale raw key references',
  );
});

test('web journal encryption rejects keys not derived by the journal crypto module', async () => {
  const importedKey = await webcrypto.subtle.importKey(
    'raw',
    webcrypto.getRandomValues(new Uint8Array(32)),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );

  await assert.rejects(
    () => encryptJournalData('untracked web key plaintext', importedKey),
    /not derived by client-side journal key derivation/,
  );
});

after(() => {
  console.log(`web crypto smoke proof: ${webCryptoSmokeProofMarkers.join(', ')}`);
});
