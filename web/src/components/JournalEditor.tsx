import React, { useState, useEffect } from 'react';
import {
  createJournalCryptoKeyHandle,
  decryptJournalData,
  deriveIsolationKey,
  disposeJournalCryptoKey,
  encryptJournalData,
  EncryptedPayload,
  getJournalCryptoKey,
  JournalCryptoKeyHandle,
  journalAssociatedData,
} from '../lib/crypto';
import { EncryptedJournalEntry, getJournalBootstrap, JournalBootstrap, listJournalEntries, saveJournalEntry } from '../lib/api';
import { useAppStore } from '../lib/store';

// Client-side zero-knowledge journal editor. Plaintext never leaves this component.
export const JournalEditor: React.FC = () => {
  const { currentRole, token, userId, organizationId } = useAppStore();
  const [plaintext, setPlaintext] = useState<string>('');
  const [passphrase, setPassphrase] = useState<string>('');
  const [encryptedData, setEncryptedData] = useState<EncryptedPayload | null>(null);
  const [entries, setEntries] = useState<EncryptedJournalEntry[]>([]);
  const [keyHandle, setKeyHandle] = useState<JournalCryptoKeyHandle | null>(null);
  const [journalBootstrap, setJournalBootstrap] = useState<JournalBootstrap | null>(null);
  const [status, setStatus] = useState<string>('');

  // Derive the key automatically when passphrase is provided
  useEffect(() => {
    let isMounted = true;
    setKeyHandle((previous) => {
      disposeJournalCryptoKey(previous);
      return null;
    });
    if (passphrase.length >= 8 && journalBootstrap?.salt_id) {
      deriveIsolationKey(passphrase, journalBootstrap.salt_id)
        .then((key) => {
          const derivedHandle = createJournalCryptoKeyHandle(key);
          if (isMounted) {
            setKeyHandle((previous) => {
              disposeJournalCryptoKey(previous);
              return derivedHandle;
            });
            setStatus("Isolation Key Derived Successfully");
          } else {
            disposeJournalCryptoKey(derivedHandle);
          }
        })
        .catch((err) => {
          console.error("Failed to derive isolation key:", err);
          if (isMounted) setStatus("Failed to derive isolation key");
        });
    } else {
      setKeyHandle((previous) => {
        disposeJournalCryptoKey(previous);
        return null;
      });
      setStatus("Awaiting valid passphrase (min 8 chars)");
    }
    return () => {
      isMounted = false;
      setKeyHandle((previous) => {
        disposeJournalCryptoKey(previous);
        return null;
      });
    };
  }, [passphrase, journalBootstrap?.salt_id]);

  const principalRef = React.useRef<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    const principal = userId && organizationId ? `${userId}:${organizationId}` : null;
    const principalChanged = principalRef.current !== principal;
    principalRef.current = principal;
    const isCurrentPrincipal = () => {
      const current = useAppStore.getState();
      return isMounted && current.userId === userId && current.organizationId === organizationId;
    };

    if (!token || !userId || !organizationId) {
      if (principalChanged || !token) {
        setJournalBootstrap(null);
        setEntries([]);
        setPlaintext('');
        setPassphrase('');
        setEncryptedData(null);
        setStatus('Sign in before using the journal.');
        setKeyHandle((previous) => {
          disposeJournalCryptoKey(previous);
          return null;
        });
      }
      return () => {
        isMounted = false;
      };
    }

    if (principalChanged) {
      setJournalBootstrap(null);
      setEntries([]);
      setPlaintext('');
      setPassphrase('');
      setEncryptedData(null);
      setKeyHandle((previous) => {
        disposeJournalCryptoKey(previous);
        return null;
      });
    }

    getJournalBootstrap(token)
      .then((bootstrap) => {
        if (isCurrentPrincipal()) setJournalBootstrap(bootstrap);
      })
      .catch((err) => {
        console.error("Failed to fetch journal bootstrap:", err);
        if (isCurrentPrincipal()) setJournalBootstrap(null);
      });
    listJournalEntries(token)
      .then((nextEntries) => {
        if (isCurrentPrincipal()) setEntries(nextEntries);
      })
      .catch((err) => {
        console.error("Failed to fetch journal entries:", err);
        if (isCurrentPrincipal()) setEntries([]);
      });

    return () => {
      isMounted = false;
    };
  }, [token, userId, organizationId]);

  // Ensure key is cleared upon dismount (Zero-Knowledge rule)
  useEffect(() => {
    return () => {
      setKeyHandle((previous) => {
        disposeJournalCryptoKey(previous);
        return null;
      });
      setPassphrase('');
    };
  }, []);

  const handleSaveToNetwork = async (): Promise<void> => {
    if (!keyHandle || plaintext.trim() === '') return;

    try {
      if (!journalBootstrap) {
        setStatus("Journal bootstrap unavailable.");
        return;
      }
      const payload = await encryptJournalData(
        plaintext,
        getJournalCryptoKey(keyHandle),
        journalAssociatedData(journalBootstrap.salt_id, journalBootstrap.salt_version),
      );
      setEncryptedData(payload);
      setPlaintext('');
      setKeyHandle((previous) => {
        disposeJournalCryptoKey(previous);
        return null;
      });
      setStatus("Successfully encrypted to opaque payload. Ready for network.");

      if (token && userId && organizationId) {
        const saved = await saveJournalEntry(token, { ...payload, salt_id: journalBootstrap.salt_id, salt_version: journalBootstrap.salt_version });
        const current = useAppStore.getState();
        if (current.userId === userId && current.organizationId === organizationId) {
          setEntries((currentEntries) => [saved, ...currentEntries]);
        }
      }

    } catch (err) {
      console.error("Encryption failed:", err);
      setStatus("Encryption failed");
    }
  };

  const handleReadFromNetwork = async (entry?: EncryptedPayload): Promise<void> => {
    const payload = entry ?? encryptedData;
    if (!keyHandle || !payload) return;
    const entrySalt = payload as Partial<EncryptedJournalEntry>;
    const associatedData = entrySalt.salt_id && typeof entrySalt.salt_version === 'number'
      ? journalAssociatedData(entrySalt.salt_id, entrySalt.salt_version)
      : journalBootstrap
        ? journalAssociatedData(journalBootstrap.salt_id, journalBootstrap.salt_version)
        : undefined;
    if (!associatedData) {
      setStatus("Journal bootstrap unavailable.");
      return;
    }

    try {
      const decodedText = await decryptJournalData(payload, getJournalCryptoKey(keyHandle), associatedData);
      const current = useAppStore.getState();
      if (current.userId === userId && current.organizationId === organizationId) {
        setPlaintext(decodedText);
        setStatus("Successfully decrypted from network payload.");
      }
    } catch (err) {
      console.error("Decryption failed:", err);
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
          disabled={!token || !keyHandle || plaintext === ''}
          className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50"
        >
          Encrypt & Save
        </button>
        <button
          onClick={() => void handleReadFromNetwork()}
          disabled={!keyHandle || !encryptedData}
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
