// Secure journal crypto for React Native.
// Production builds must provide WebCrypto-compatible AES-GCM through the
// platform runtime or the native react-native-quick-crypto JSI binding.
import { Buffer } from 'buffer';

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
}

export type JournalCryptoKey = object;

export interface JournalCryptoKeyHandle {
  key: JournalCryptoKey | null;
  disposed: boolean;
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
    algorithm: { name: string; iv: Uint8Array },
    key: JournalCryptoKey,
    data: Uint8Array,
  ): Promise<ArrayBuffer>;
  decrypt(
    algorithm: { name: string; iv: Uint8Array },
    key: JournalCryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer>;
}

interface CryptoProvider {
  subtle: SubtleCryptoLike;
  getRandomValues<T extends Uint8Array>(array: T): T;
}

interface QuickCryptoModule {
  webcrypto?: CryptoProvider;
  crypto?: { webcrypto?: CryptoProvider };
}

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

function getCryptoProvider(): CryptoProvider {
  const provider = getGlobalCrypto() ?? getQuickCrypto();
  if (!provider) {
    throw new Error(
      'Secure journal crypto provider unavailable. Install/configure react-native-quick-crypto or a WebCrypto AES-GCM runtime before enabling journal storage.',
    );
  }
  return provider;
}

function stringToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function wipeBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}

function bufferToBase64(value: ArrayBuffer | Uint8Array): string {
  return Buffer.from(value instanceof Uint8Array ? value : new Uint8Array(value)).toString('base64');
}

function base64ToBuffer(value: string): ArrayBuffer {
  const bytes = Buffer.from(value, 'base64');
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Derives a non-extractable AES-256-GCM key using PBKDF2 from a user passphrase.
 */
export async function deriveIsolationKey(passphrase: string, salt: string): Promise<JournalCryptoKey> {
  const provider = getCryptoProvider();
  const passphraseBytes = stringToBytes(passphrase);
  const saltBytes = stringToBytes(salt);
  const keyMaterial = await provider.subtle.importKey(
    'raw',
    passphraseBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey'],
  );

  try {
    return await provider.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 210000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
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
  handle.key = null;
  handle.disposed = true;
}

/**
 * Encrypts plaintext with authenticated AES-256-GCM before any journal network write.
 */
export async function encryptJournalData(
  plaintext: string,
  key: JournalCryptoKey,
): Promise<EncryptedPayload> {
  const provider = getCryptoProvider();
  const iv = provider.getRandomValues(new Uint8Array(12));
  const ciphertext = await provider.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    stringToBytes(plaintext),
  );

  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv),
  };
}

/**
 * Decrypts an opaque AES-GCM journal payload entirely on the client.
 */
export async function decryptJournalData(payload: EncryptedPayload, key: JournalCryptoKey): Promise<string> {
  const provider = getCryptoProvider();
  const plaintext = await provider.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(base64ToBuffer(payload.iv)) },
    key,
    base64ToBuffer(payload.ciphertext),
  );
  return new TextDecoder().decode(plaintext);
}
