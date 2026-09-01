import React, { useState, useEffect, useRef } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet } from 'react-native';
import {
  createJournalCryptoKeyHandle,
  decryptJournalData,
  deriveIsolationKey,
  disposeJournalCryptoKey,
  encryptJournalData,
  EncryptedPayload,
  getJournalCryptoKey,
  journalAssociatedData,
  JournalCryptoKeyHandle,
} from '../lib/crypto';
import {
  EncryptedJournalEntry,
  getJournalBootstrap,
  getJournalEntry,
  JournalBootstrap,
  listJournalEntries,
  saveJournalEntry,
} from '../lib/api';
import { useAppStore } from '../lib/store';

export const SecureJournalContainer: React.FC = () => {
  const [plaintext, setPlaintext] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [status, setStatus] = useState('Awaiting passphrase');
  const [keyHandle, setKeyHandle] = useState<JournalCryptoKeyHandle | null>(null);
  const [journalBootstrap, setJournalBootstrap] = useState<JournalBootstrap | null>(null);
  const [entries, setEntries] = useState<EncryptedJournalEntry[]>([]);
  const preserveDerivedHandleOnPassphraseClear = useRef(false);
  const identityGeneration = useRef(0);
  const session = useAppStore((state) => state.session);

  useEffect(() => {
    let isMounted = true;
    const generation = ++identityGeneration.current;
    preserveDerivedHandleOnPassphraseClear.current = false;
    setJournalBootstrap(null);
    setEntries([]);
    setPlaintext('');
    setPassphrase('');
    setKeyHandle(previous => {
      disposeJournalCryptoKey(previous);
      return null;
    });

    if (!session) {
      return () => {
        isMounted = false;
      };
    }

    const accessToken = session.token;
    getJournalBootstrap(accessToken)
      .then((bootstrap) => {
        if (isMounted && identityGeneration.current === generation) setJournalBootstrap(bootstrap);
      })
      .catch(() => {
        if (isMounted && identityGeneration.current === generation) setJournalBootstrap(null);
      });
    listJournalEntries(accessToken)
      .then((nextEntries) => {
        if (isMounted && identityGeneration.current === generation) setEntries(nextEntries);
      })
      .catch(() => {
        if (isMounted && identityGeneration.current === generation) setEntries([]);
      });

    return () => {
      isMounted = false;
    };
  }, [session?.user_id, session?.organization_id]);

  useEffect(() => {
    return () => {
      setKeyHandle((previous) => {
        disposeJournalCryptoKey(previous);
        return null;
      });
    };
  }, []);

  useEffect(() => {
    let isMounted = true;
    let activeHandle: JournalCryptoKeyHandle | null = null;
    if (passphrase.length >= 8 && journalBootstrap?.salt_id) {
      preserveDerivedHandleOnPassphraseClear.current = false;
      deriveIsolationKey(passphrase, journalBootstrap.salt_id)
        .then(k => {
          const derivedHandle = createJournalCryptoKeyHandle(k);
          if (isMounted) {
            activeHandle = derivedHandle;
            setKeyHandle(previous => {
              disposeJournalCryptoKey(previous);
              return activeHandle;
            });
            preserveDerivedHandleOnPassphraseClear.current = true;
            setPassphrase('');
            setStatus("Isolation Key Derived Successfully");
          } else {
            disposeJournalCryptoKey(derivedHandle);
          }
        })
        .catch((error: Error) => {
          if (isMounted) {
            setKeyHandle(previous => {
              disposeJournalCryptoKey(previous);
              return null;
            });
            setPassphrase('');
            setStatus(error.message);
          }
        });
    } else if (passphrase.length > 0) {
      setStatus("Awaiting valid passphrase (min 8 chars)");
      setKeyHandle(previous => {
        disposeJournalCryptoKey(previous);
        return null;
      });
    }
    return () => {
      isMounted = false;
      setKeyHandle(previous => {
        if (previous === activeHandle && preserveDerivedHandleOnPassphraseClear.current) {
          preserveDerivedHandleOnPassphraseClear.current = false;
          return previous;
        }
        if (previous === activeHandle) {
          disposeJournalCryptoKey(previous);
          return null;
        }
        disposeJournalCryptoKey(activeHandle);
        return previous;
      });
    };
  }, [passphrase, journalBootstrap?.salt_id]);

  const handleSave = async () => {
    if (keyHandle && plaintext) {
      if (!session) {
        setStatus('Sign in before saving encrypted journal entries.');
        return;
      }
      if (!journalBootstrap) {
        setStatus('Journal bootstrap unavailable.');
        return;
      }
      const generation = identityGeneration.current;
      const identity = { user_id: session.user_id, organization_id: session.organization_id };
      try {
        const encrypted: EncryptedPayload = await encryptJournalData(
          plaintext,
          getJournalCryptoKey(keyHandle),
          journalAssociatedData(journalBootstrap.salt_id, journalBootstrap.salt_version),
        );
        const saved = await saveJournalEntry(session.token, {
          ...encrypted,
          salt_id: journalBootstrap.salt_id,
          salt_version: journalBootstrap.salt_version,
        });
        const currentSession = useAppStore.getState().session;
        if (identityGeneration.current !== generation || !currentSession
          || currentSession.user_id !== identity.user_id
          || currentSession.organization_id !== identity.organization_id) return;
        setEntries((current) => [saved, ...current.filter((entry) => entry.id !== saved.id)]);
        setPlaintext('');
        setStatus(`Saved securely! IV: ${encrypted.iv.substring(0, 10)}...`);
      } catch {
        if (identityGeneration.current === generation) setStatus('Journal save failed.');
      }
    }
  };

  const handleLoad = async (entry: EncryptedJournalEntry) => {
    if (!session) {
      setStatus('Sign in before loading encrypted journal entries.');
      return;
    }
    if (!keyHandle) {
      setStatus('Enter your passphrase before loading an entry.');
      return;
    }

    const generation = identityGeneration.current;
    const identity = { user_id: session.user_id, organization_id: session.organization_id };
    try {
      const stored = await getJournalEntry(session.token, entry.id);
      const associatedData = journalAssociatedData(stored.salt_id, stored.salt_version);
      const decodedText = await decryptJournalData(
        stored,
        getJournalCryptoKey(keyHandle),
        associatedData,
      );
      const currentSession = useAppStore.getState().session;
      if (identityGeneration.current !== generation || !currentSession
        || currentSession.user_id !== identity.user_id
        || currentSession.organization_id !== identity.organization_id) return;
      setPlaintext(decodedText);
      setStatus('Loaded and decrypted locally.');
    } catch {
      setStatus('Decryption failed. Invalid key or corrupted data.');
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Zero-Knowledge Journal (Mobile)</Text>

      <Text style={styles.identity}>
        {session ? `Signed in as ${session.user_id}` : 'Sign in to save encrypted entries.'}
      </Text>

      <TextInput
        style={styles.input}
        secureTextEntry
        placeholder="Decryption Passphrase"
        value={passphrase}
        onChangeText={setPassphrase}
      />
      <Text style={styles.status}>{status}</Text>

      <TextInput
        style={[styles.input, styles.textArea]}
        multiline
        placeholder="Write your private theological notes here..."
        value={plaintext}
        onChangeText={setPlaintext}
      />

      <TouchableOpacity
        style={[styles.button, (!session || !keyHandle || !plaintext) && styles.disabled]}
        onPress={() => void handleSave()}
        disabled={!session || !keyHandle || !plaintext}
      >
        <Text style={styles.buttonText}>Encrypt & Save</Text>
      </TouchableOpacity>

      {entries.length > 0 && (
        <View style={styles.entries}>
          <Text style={styles.entriesTitle}>Saved encrypted entries</Text>
          {entries.map((entry) => (
            <TouchableOpacity
              key={entry.id}
              style={styles.entry}
              onPress={() => void handleLoad(entry)}
            >
              <Text style={styles.entryText}>{entry.id}</Text>
              <Text style={styles.entryAction}>Load & decrypt</Text>
            </TouchableOpacity>
          ))}
        </View>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: { padding: 16, backgroundColor: '#fff', borderRadius: 8, margin: 16, elevation: 3 },
  title: { fontSize: 20, fontWeight: 'bold', marginBottom: 16, color: '#111827' },
  input: { borderWidth: 1, borderColor: '#D1D5DB', borderRadius: 6, padding: 10, marginBottom: 8 },
  textArea: { height: 120, textAlignVertical: 'top' },
  identity: { fontSize: 12, color: '#4B5563', marginBottom: 8 },
  status: { fontSize: 12, color: '#2563EB', marginBottom: 16 },
  button: { backgroundColor: '#4F46E5', padding: 12, borderRadius: 6, alignItems: 'center' },
  disabled: { opacity: 0.5 },
  buttonText: { color: '#fff', fontWeight: 'bold' },
  entries: { marginTop: 16, gap: 8 },
  entriesTitle: { fontSize: 14, fontWeight: '700', color: '#111827' },
  entry: { borderWidth: 1, borderColor: '#E5E7EB', borderRadius: 6, padding: 10 },
  entryText: { color: '#374151', fontSize: 12 },
  entryAction: { color: '#2563EB', fontSize: 12, marginTop: 4 }
});
