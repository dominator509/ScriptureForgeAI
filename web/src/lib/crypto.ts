// Crypto routines for client-side zero-knowledge isolation

export interface EncryptedPayload {
    ciphertext: string; // Base64 encoded
    iv: string;         // Base64 encoded
}

/**
 * Derives a 256-bit AES-GCM isolation key using PBKDF2 from a user passphrase.
 * Ensures that all cryptographic key generation happens purely client-side.
 */
export async function deriveIsolationKey(passphrase: string, salt: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    // 210,000 iterations for SHA-256 PBKDF2 is the OWASP recommended minimum for 2024
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: encoder.encode(salt),
            iterations: 210000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

/**
 * Utility to convert ArrayBuffer to Base64 string safely.
 */
function bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
    return window.btoa(binary);
}

/**
 * Utility to convert Base64 string to ArrayBuffer.
 */
function base64ToBuffer(base64: string): ArrayBuffer {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Encrypts plaintext data into a safe opaque payload using AES-256-GCM.
 * This guarantees zero-knowledge containment before network transmission.
 */
export async function encryptJournalData(plaintext: string, key: CryptoKey): Promise<EncryptedPayload> {
    const encoder = new TextEncoder();
    // GCM recommended IV size is 12 bytes (96 bits)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encoder.encode(plaintext)
    );

    return {
        ciphertext: bufferToBase64(ciphertextBuffer),
        iv: bufferToBase64(iv.buffer),
    };
}

/**
 * Decrypts an opaque AES-GCM payload back into plaintext entirely client-side.
 */
export async function decryptJournalData(payload: EncryptedPayload, key: CryptoKey): Promise<string> {
    const decoder = new TextDecoder();
    const ivBuffer = base64ToBuffer(payload.iv);
    const ciphertextBuffer = base64ToBuffer(payload.ciphertext);

    try {
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBuffer,
            },
            key,
            ciphertextBuffer
        );
        return decoder.decode(decryptedBuffer);
    } catch (e) {
        throw new Error("Failed to decrypt payload. The isolation key or data might be invalid.");
    }
}
