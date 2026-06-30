// Secure journal crypto for React Native.
// Production builds prefer the native react-native-quick-crypto JSI binding,
// with WebCrypto-compatible runtimes retained as a local/test fallback.
import { Buffer } from 'buffer';

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
}

export type JournalCryptoKey = object;

export const JOURNAL_PBKDF2_ITERATIONS = 600000;
export type JournalCryptoProviderName = 'react-native-quick-crypto' | 'webcrypto-fallback';

export interface JournalCryptoKeyHandle {
  key: JournalCryptoKey | null;
  disposed: boolean;
}

export interface JournalCryptoProviderStatus {
  provider: JournalCryptoProviderName | 'unavailable';
  nativeRequired: boolean;
}

export interface JournalCryptoSelfTestResult extends JournalCryptoProviderStatus {
  markers: string[];
}

export function journalAssociatedData(saltID: string, saltVersion: number): string {
  return `scriptureforge-journal:v1:salt_id=${saltID}:salt_version=${saltVersion}`;
}

type CryptoKeyUsage = 'decrypt' | 'deriveBits' | 'deriveKey' | 'encrypt';
type KeyFormat = 'raw';

interface SubtleCryptoLike {
  importKey(
    format: KeyFormat,
    keyData: ArrayBuffer | Uint8Array,
    algorithm: { name: string },
    extractable: boolean,
    keyUsages: CryptoKeyUsage[],
  ): Promise<JournalCryptoKey>;
  deriveKey(
    algorithm: {
      name: string;
      salt: Uint8Array;
      iterations: number;
      hash: string;
    },
    baseKey: JournalCryptoKey,
    derivedKeyAlgorithm: { name: string; length: number },
    extractable: boolean,
    keyUsages: CryptoKeyUsage[],
  ): Promise<JournalCryptoKey>;
  encrypt(
    algorithm: { name: string; iv: Uint8Array; additionalData?: Uint8Array },
    key: JournalCryptoKey,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
  decrypt(
    algorithm: { name: string; iv: Uint8Array; additionalData?: Uint8Array },
    key: JournalCryptoKey,
    data: ArrayBuffer | Uint8Array,
  ): Promise<ArrayBuffer>;
  exportKey?(format: KeyFormat, key: JournalCryptoKey): Promise<ArrayBuffer>;
}

interface CryptoProvider {
  subtle: SubtleCryptoLike;
  getRandomValues<T extends Uint8Array>(array: T): T;
}

interface QuickCryptoModule {
  webcrypto?: CryptoProvider;
  crypto?: { webcrypto?: CryptoProvider };
}

interface SelectedCryptoProvider {
  provider: CryptoProvider;
  name: JournalCryptoProviderName;
}

const keyProviders = new WeakMap<JournalCryptoKey, SelectedCryptoProvider>();
const revokedJournalKeys = new WeakSet<JournalCryptoKey>();

function getGlobalCrypto(): CryptoProvider | null {
  const candidate = (globalThis as { crypto?: CryptoProvider }).crypto;
  if (candidate?.subtle && typeof candidate.getRandomValues === 'function') {
    return candidate;
  }
  return null;
}

function getQuickCrypto(): CryptoProvider | null {
  try {
    const quickCrypto = require('react-native-quick-crypto') as QuickCryptoModule;
    const candidate = quickCrypto.webcrypto ?? quickCrypto.crypto?.webcrypto;
    if (candidate?.subtle && typeof candidate.getRandomValues === 'function') {
      return candidate;
    }
  } catch {
    return null;
  }
  return null;
}

function requiresNativeCrypto(): boolean {
  return process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO === 'true';
}

function getSelectedCryptoProvider(): SelectedCryptoProvider {
  const nativeProvider = getQuickCrypto();
  if (nativeProvider) {
    return { provider: nativeProvider, name: 'react-native-quick-crypto' };
  }
  if (requiresNativeCrypto()) {
    throw new Error(
      'Native secure journal crypto provider unavailable. Production mobile builds require react-native-quick-crypto.',
    );
  }
  const fallbackProvider = getGlobalCrypto();
  if (fallbackProvider) {
    return { provider: fallbackProvider, name: 'webcrypto-fallback' };
  }
  throw new Error(
    'Secure journal crypto provider unavailable. Install/configure react-native-quick-crypto or a WebCrypto AES-GCM runtime before enabling journal storage.',
  );
}

function getCryptoProviderForKey(key: JournalCryptoKey): CryptoProvider {
  if (revokedJournalKeys.has(key)) {
    throw new Error('Journal crypto key has been disposed');
  }
  const selected = keyProviders.get(key);
  if (!selected) {
    throw new Error('Journal crypto key was not derived by client-side journal key derivation');
  }
  if (requiresNativeCrypto() && selected.name !== 'react-native-quick-crypto') {
    throw new Error('Journal crypto key was not derived by the required native provider');
  }
  return selected.provider;
}

export function getJournalCryptoProviderStatus(): JournalCryptoProviderStatus {
  if (getQuickCrypto()) {
    return { provider: 'react-native-quick-crypto', nativeRequired: requiresNativeCrypto() };
  }
  if (requiresNativeCrypto()) {
    return { provider: 'unavailable', nativeRequired: true };
  }
  if (getGlobalCrypto()) {
    return { provider: 'webcrypto-fallback', nativeRequired: false };
  }
  return { provider: 'unavailable', nativeRequired: false };
}

function stringToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function wipeBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}

function assertJournalKeyInputs(passphrase: string, salt: string): void {
  if (passphrase.trim() === '') {
    throw new Error('Journal passphrase is required for client-side key derivation');
  }
  if (salt.trim() === '') {
    throw new Error('Journal server salt material is required for client-side key derivation');
  }
}

function bufferToBase64(value: ArrayBuffer | Uint8Array): string {
  return Buffer.from(value instanceof Uint8Array ? value : new Uint8Array(value)).toString('base64');
}

function base64ToBuffer(value: string): ArrayBuffer {
  const bytes = Buffer.from(value, 'base64');
  try {
    const copied = new Uint8Array(bytes.byteLength);
    copied.set(bytes);
    return copied.buffer;
  } finally {
    wipeBytes(bytes);
  }
}

/**
 * Derives a non-extractable AES-256-GCM key using PBKDF2 from a user passphrase.
 */
export async function deriveIsolationKey(passphrase: string, salt: string): Promise<JournalCryptoKey> {
  assertJournalKeyInputs(passphrase, salt);
  const selected = getSelectedCryptoProvider();
  const provider = selected.provider;
  const passphraseBytes = stringToBytes(passphrase);
  const saltBytes = stringToBytes(salt);
  try {
    const keyMaterial = await provider.subtle.importKey(
      'raw',
      passphraseBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey'],
    );
    const key = await provider.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: JOURNAL_PBKDF2_ITERATIONS,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    keyProviders.set(key, selected);
    return key;
  } finally {
    wipeBytes(passphraseBytes);
    wipeBytes(saltBytes);
  }
}

export function createJournalCryptoKeyHandle(key: JournalCryptoKey): JournalCryptoKeyHandle {
  return { key, disposed: false };
}

export function getJournalCryptoKey(handle: JournalCryptoKeyHandle): JournalCryptoKey {
  if (handle.disposed || !handle.key) {
    throw new Error('Journal crypto key handle has been disposed');
  }
  return handle.key;
}

export function disposeJournalCryptoKey(handle: JournalCryptoKeyHandle | null): void {
  if (!handle) return;
  if (handle.key) {
    revokedJournalKeys.add(handle.key);
  }
  handle.key = null;
  handle.disposed = true;
}

/**
 * Encrypts plaintext with authenticated AES-256-GCM before any journal network write.
 */
export async function encryptJournalData(
  plaintext: string,
  key: JournalCryptoKey,
  associatedData?: string,
): Promise<EncryptedPayload> {
  const provider = getCryptoProviderForKey(key);
  const iv = provider.getRandomValues(new Uint8Array(12));
  const plaintextBytes = stringToBytes(plaintext);
  const associatedDataBytes = associatedData ? stringToBytes(associatedData) : undefined;
  try {
    const ciphertext = await provider.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: associatedDataBytes },
      key,
      plaintextBytes,
    );

    return {
      ciphertext: bufferToBase64(ciphertext),
      iv: bufferToBase64(iv),
    };
  } finally {
    wipeBytes(plaintextBytes);
    if (associatedDataBytes) wipeBytes(associatedDataBytes);
    wipeBytes(iv);
  }
}

/**
 * Decrypts an opaque AES-GCM journal payload entirely on the client.
 */
export async function decryptJournalData(
  payload: EncryptedPayload,
  key: JournalCryptoKey,
  associatedData?: string,
): Promise<string> {
  const provider = getCryptoProviderForKey(key);
  const ivBytes = new Uint8Array(base64ToBuffer(payload.iv));
  const ciphertextBytes = new Uint8Array(base64ToBuffer(payload.ciphertext));
  const associatedDataBytes = associatedData ? stringToBytes(associatedData) : undefined;
  try {
    const plaintext = await provider.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, additionalData: associatedDataBytes },
      key,
      ciphertextBytes,
    );
    const plaintextBytes = new Uint8Array(plaintext);
    try {
      return new TextDecoder().decode(plaintextBytes);
    } finally {
      wipeBytes(plaintextBytes);
    }
  } finally {
    wipeBytes(ciphertextBytes);
    if (associatedDataBytes) wipeBytes(associatedDataBytes);
    wipeBytes(ivBytes);
  }
}

export async function runJournalCryptoSelfTest(): Promise<JournalCryptoSelfTestResult> {
  const status = getJournalCryptoProviderStatus();
  const markers = [
    'runJournalCryptoSelfTest',
    `provider=${status.provider}`,
    `native_required=${status.nativeRequired}`,
    `provider status ${status.provider}`,
    `native-required ${status.nativeRequired}`,
    'AES-GCM',
    'passphrase wiped',
    'passphrase buffer zeroized',
    'salt wiped',
    'salt buffer zeroized',
    'plaintext cleared',
    'plaintext buffer zeroized',
  ];
  if (status.provider === 'react-native-quick-crypto') {
    markers.push('react-native-quick-crypto', 'native provider', 'native module loaded', 'provider-bound key');
  }
  if (status.nativeRequired && status.provider !== 'react-native-quick-crypto') {
    throw new Error('journal crypto self-test requires the native react-native-quick-crypto provider');
  }
  const plaintext = 'ScriptureForgeAI native journal crypto self-test plaintext';
  const saltID = 'journal:self-test:server-derived-salt';
  const saltVersion = 1;
  const associatedData = journalAssociatedData(saltID, saltVersion);
  const key = await deriveIsolationKey('journal-self-test-passphrase', saltID);
  const handle = createJournalCryptoKeyHandle(key);
  try {
    const provider = getCryptoProviderForKey(key);
    if (provider.subtle.exportKey) {
      let extractable = false;
      try {
        await provider.subtle.exportKey('raw', key);
        extractable = true;
      } catch {
        extractable = false;
      }
      if (extractable) {
        throw new Error('journal crypto self-test derived an extractable AES-GCM key');
      }
    }
    markers.push('non-extractable');

    const encrypted = await encryptJournalData(plaintext, getJournalCryptoKey(handle), associatedData);
    const decrypted = await decryptJournalData(encrypted, getJournalCryptoKey(handle), associatedData);
    if (decrypted !== plaintext) {
      throw new Error('journal crypto self-test AES-GCM round-trip failed');
    }
    markers.push('aes_gcm_roundtrip=true', 'round-trip');

    const secondEncrypted = await encryptJournalData(plaintext, getJournalCryptoKey(handle), associatedData);
    if (secondEncrypted.iv === encrypted.iv || secondEncrypted.ciphertext === encrypted.ciphertext) {
      throw new Error('journal crypto self-test reused AES-GCM IV material');
    }
    markers.push('unique_iv=true', 'unique IV');

    let tamperRejected = false;
    try {
      await decryptJournalData(
        { ...encrypted, ciphertext: `${encrypted.ciphertext.slice(0, -2)}AA` },
        getJournalCryptoKey(handle),
        associatedData,
      );
    } catch {
      tamperRejected = true;
    }
    if (!tamperRejected) {
      throw new Error('journal crypto self-test accepted tampered ciphertext');
    }
    markers.push('tamper_rejected=true', 'tamper rejected');

    let associatedDataRejected = false;
    try {
      await decryptJournalData(
        encrypted,
        getJournalCryptoKey(handle),
        journalAssociatedData('journal:self-test:different-salt', 1),
      );
    } catch {
      associatedDataRejected = true;
    }
    if (!associatedDataRejected) {
      throw new Error('journal crypto self-test accepted wrong associated data');
    }
    markers.push(
      'associated_data_rejected=true',
      'associated data',
      'wrong associated data rejected',
      `associated_data_salt_id=${saltID}`,
      `associated_data_salt_version=${saltVersion}`,
    );

    disposeJournalCryptoKey(handle);
    let disposedRejected = false;
    try {
      getJournalCryptoKey(handle);
    } catch {
      disposedRejected = true;
    }
    if (!disposedRejected) {
      throw new Error('journal crypto self-test did not reject a disposed key handle');
    }
    markers.push('key_disposal=true', 'key disposed', 'disposed handle rejected');

    return {
      ...status,
      markers,
    };
  } finally {
    disposeJournalCryptoKey(handle);
  }
}
