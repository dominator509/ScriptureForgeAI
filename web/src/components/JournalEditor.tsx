import React, { useState, useEffect } from 'react';
import { deriveIsolationKey, encryptJournalData, decryptJournalData, EncryptedPayload } from '../lib/crypto';
import { EncryptedJournalEntry, listJournalEntries, saveJournalEntry } from '../lib/api';
import { useAppStore } from '../lib/store';

// A fully functional component demonstrating Zero-Knowledge containment integrations
export const JournalEditor: React.FC = () => {
  const { currentRole, token, userId } = useAppStore();
  const [plaintext, setPlaintext] = useState<string>('');
  const [passphrase, setPassphrase] = useState<string>('');
  const [encryptedData, setEncryptedData] = useState<EncryptedPayload | null>(null);
  const [entries, setEntries] = useState<EncryptedJournalEntry[]>([]);
  const [cryptoKey, setCryptoKey] = useState<CryptoKey | null>(null);
  const [status, setStatus] = useState<string>('');

  const userSalt = userId ? `journal:${userId}:v1` : '';

  // Derive the key automatically when passphrase is provided
  useEffect(() => {
    let isMounted = true;
    if (passphrase.length >= 8 && userSalt) {
      deriveIsolationKey(passphrase, userSalt)
        .then((key) => {
          if (isMounted) {
            setCryptoKey(key);
            setStatus("Isolation Key Derived Successfully");
          }
        })
        .catch(() => {
          if (isMounted) setStatus("Failed to derive isolation key");
        });
    } else {
      setCryptoKey(null);
      setStatus("Awaiting valid passphrase (min 8 chars)");
    }
    return () => { isMounted = false; };
  }, [passphrase, userSalt]);

  useEffect(() => {
    if (!token) return;
    listJournalEntries(token)
      .then(setEntries)
      .catch(() => setEntries([]));
  }, [token]);

  // Ensure key is cleared upon dismount (Zero-Knowledge rule)
  useEffect(() => {
    return () => {
      setCryptoKey(null);
      setPassphrase('');
    };
  }, []);

  const handleSaveToNetwork = async (): Promise<void> => {
    if (!cryptoKey || plaintext.trim() === '') return;

    try {
      const payload = await encryptJournalData(plaintext, cryptoKey);
      setEncryptedData(payload);
      setStatus("Successfully encrypted to opaque payload. Ready for network.");

      if (token) {
        const saved = await saveJournalEntry(token, { ...payload, salt_id: userSalt, salt_version: 1 });
        setEntries((current) => [saved, ...current]);
      }

    } catch (err) {
      setStatus("Encryption failed");
    }
  };

  const handleReadFromNetwork = async (entry?: EncryptedPayload): Promise<void> => {
    const payload = entry ?? encryptedData;
    if (!cryptoKey || !payload) return;

    try {
      const decodedText = await decryptJournalData(payload, cryptoKey);
      setPlaintext(decodedText);
      setStatus("Successfully decrypted from network payload.");
    } catch (err) {
      setStatus("Decryption failed. Invalid key or corrupted data.");
    }
  };

  return (
    <div className="p-6 max-w-2xl mx-auto bg-white rounded-xl shadow-md space-y-4">
      <h2 className="text-2xl font-bold text-gray-900">Zero-Knowledge Journal</h2>
      <p className="text-sm text-gray-500">Current Role: {currentRole}</p>
      {!token && <p className="text-sm text-red-600">Sign in before saving encrypted journal entries.</p>}

      <div>
        <label className="block text-sm font-medium text-gray-700">Decryption Passphrase</label>
        <input
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
          placeholder="Enter min 8 characters..."
        />
        <p className="text-xs text-blue-600 mt-1">Status: {status}</p>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700">Journal Entry</label>
        <textarea
          value={plaintext}
          onChange={(e) => setPlaintext(e.target.value)}
          rows={5}
          className="mt-1 block w-full rounded-md border-gray-300 shadow-sm p-2 border"
          placeholder="Write your private theological notes here..."
        />
      </div>

      <div className="flex space-x-4">
        <button
          onClick={() => void handleSaveToNetwork()}
          disabled={!token || !cryptoKey || plaintext === ''}
          className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50"
        >
          Encrypt & Save
        </button>
        <button
          onClick={() => void handleReadFromNetwork()}
          disabled={!cryptoKey || !encryptedData}
          className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
        >
          Read & Decrypt
        </button>
      </div>

      {encryptedData && (
        <div className="mt-4 p-4 bg-gray-100 rounded text-xs break-all overflow-hidden">
          <strong>Opaque Network Payload (Zero-Knowledge):</strong><br/>
          <span className="font-mono text-gray-700">
            {JSON.stringify(encryptedData)}
          </span>
        </div>
      )}
      {entries.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold text-gray-800">Saved Entries</h3>
          {entries.map((entry) => (
            <button
              key={entry.id}
              onClick={() => void handleReadFromNetwork(entry)}
              className="block w-full text-left px-3 py-2 border rounded text-xs text-gray-700"
            >
              {entry.id}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
