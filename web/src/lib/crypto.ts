// Crypto routines for client-side zero-knowledge isolation.

export interface EncryptedPayload {
    ciphertext: string; // Base64 encoded
    iv: string;         // Base64 encoded
}

type CryptoKeyUsage = 'decrypt' | 'deriveBits' | 'deriveKey' | 'encrypt';

export interface JournalCryptoKeyHandle {
    key: CryptoKey | null;
    disposed: boolean;
}

export const JOURNAL_PBKDF2_ITERATIONS = 600000;
const derivedJournalKeys = new WeakSet<CryptoKey>();
const revokedJournalKeys = new WeakSet<CryptoKey>();

export function journalAssociatedData(saltID: string, saltVersion: number): string {
    if (saltID.trim() === '') {
        throw new Error('Journal associated data requires a server salt identifier');
    }
    if (!Number.isInteger(saltVersion) || saltVersion <= 0) {
        throw new Error('Journal associated data requires a positive integer salt version');
    }
    return `scriptureforge-journal:v1:salt_id=${saltID}:salt_version=${saltVersion}`;
}

function assertJournalKeyInputs(passphrase: string, salt: string): void {
    if (passphrase.trim() === '') {
        throw new Error('Journal passphrase is required for client-side key derivation');
    }
    if (salt.trim() === '') {
        throw new Error('Journal server salt material is required for client-side key derivation');
    }
}

function bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i += 1) {
        binary += String.fromCharCode(bytes[i]!);
    }
    return window.btoa(binary);
}

function base64ToBuffer(base64: string): ArrayBuffer {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i += 1) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Derives a 256-bit AES-GCM isolation key using PBKDF2 from a user passphrase.
 * Ensures that all cryptographic key generation happens purely client-side.
 */
export async function deriveIsolationKey(passphrase: string, salt: string): Promise<CryptoKey> {
    assertJournalKeyInputs(passphrase, salt);
    const encoder = new TextEncoder();
    const passphraseBytes = encoder.encode(passphrase);
    const saltBytes = encoder.encode(salt);

    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        passphraseBytes,
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"] as CryptoKeyUsage[]
    );
    try {
        // Match the architecture's journal key-derivation work factor.
        const key = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: JOURNAL_PBKDF2_ITERATIONS,
                hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"] as CryptoKeyUsage[]
        );
        derivedJournalKeys.add(key);
        return key;
    } finally {
        passphraseBytes.fill(0);
        saltBytes.fill(0);
    }
}

export function createJournalCryptoKeyHandle(key: CryptoKey): JournalCryptoKeyHandle {
    return { key, disposed: false };
}

export function getJournalCryptoKey(handle: JournalCryptoKeyHandle): CryptoKey {
    if (handle.disposed || !handle.key) {
        throw new Error("Journal crypto key handle has been disposed");
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

function assertUsableJournalCryptoKey(key: CryptoKey): void {
    if (revokedJournalKeys.has(key)) {
        throw new Error("Journal crypto key has been disposed");
    }
    if (!derivedJournalKeys.has(key)) {
        throw new Error("Journal crypto key was not derived by client-side journal key derivation");
    }
}

/**
 * Encrypts plaintext data into a safe opaque payload using AES-256-GCM.
 * This guarantees zero-knowledge containment before network transmission.
 */
export async function encryptJournalData(plaintext: string, key: CryptoKey, associatedData?: string): Promise<EncryptedPayload> {
    assertUsableJournalCryptoKey(key);
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);
    const associatedDataBytes = associatedData ? encoder.encode(associatedData) : undefined;
    // GCM recommended IV size is 12 bytes (96 bits)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    try {
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                additionalData: associatedDataBytes,
            },
            key,
            plaintextBytes
        );

        return {
            ciphertext: bufferToBase64(ciphertextBuffer),
            iv: bufferToBase64(iv.buffer),
        };
    } finally {
        plaintextBytes.fill(0);
        associatedDataBytes?.fill(0);
        iv.fill(0);
    }
}

/**
 * Decrypts an opaque AES-GCM payload back into plaintext entirely client-side.
 */
export async function decryptJournalData(payload: EncryptedPayload, key: CryptoKey, associatedData?: string): Promise<string> {
    assertUsableJournalCryptoKey(key);
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    const ivBuffer = base64ToBuffer(payload.iv);
    const ciphertextBuffer = base64ToBuffer(payload.ciphertext);
    const ivBytes = new Uint8Array(ivBuffer);
    const ciphertextBytes = new Uint8Array(ciphertextBuffer);
    const associatedDataBytes = associatedData ? encoder.encode(associatedData) : undefined;
    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBytes,
                additionalData: associatedDataBytes,
            },
            key,
            ciphertextBytes
        );
        try {
            return decoder.decode(new Uint8Array(decryptedBuffer));
        } finally {
            const decryptedBytes = new Uint8Array(decryptedBuffer);
            decryptedBytes.fill(0);
        }
    } catch (e) {
        throw new Error("Failed to decrypt payload. The isolation key or data might be invalid.");
    } finally {
        ivBytes.fill(0);
        ciphertextBytes.fill(0);
        associatedDataBytes?.fill(0);
    }
}
