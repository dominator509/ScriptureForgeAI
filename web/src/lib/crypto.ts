// Crypto routines for client-side zero-knowledge isolation.

export interface EncryptedPayload {
    ciphertext: string; // Base64 encoded
    iv: string;         // Base64 encoded
}

type CryptoKeyUsage = 'decrypt' | 'deriveBits' | 'deriveKey' | 'encrypt';

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
        // 210,000 iterations for SHA-256 PBKDF2 is the OWASP recommended minimum for 2024.
        return await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: 210000,
                hash: "SHA-256",
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"] as CryptoKeyUsage[]
        );
    } finally {
        passphraseBytes.fill(0);
        saltBytes.fill(0);
    }
}

/**
 * Encrypts plaintext data into a safe opaque payload using AES-256-GCM.
 * This guarantees zero-knowledge containment before network transmission.
 */
export async function encryptJournalData(plaintext: string, key: CryptoKey): Promise<EncryptedPayload> {
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);
    // GCM recommended IV size is 12 bytes (96 bits)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    try {
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
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
        iv.fill(0);
    }
}

/**
 * Decrypts an opaque AES-GCM payload back into plaintext entirely client-side.
 */
export async function decryptJournalData(payload: EncryptedPayload, key: CryptoKey): Promise<string> {
    const decoder = new TextDecoder();
    const ivBuffer = base64ToBuffer(payload.iv);
    const ciphertextBuffer = base64ToBuffer(payload.ciphertext);
    const ivBytes = new Uint8Array(ivBuffer);
    const ciphertextBytes = new Uint8Array(ciphertextBuffer);
    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBytes,
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
    }
}
