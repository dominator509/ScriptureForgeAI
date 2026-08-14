import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet } from 'react-native';
import { deriveIsolationKey, encryptJournalData, EncryptedPayload } from '../lib/crypto';
import { apiRequest } from '../lib/api';
import { useAppStore } from '../lib/store';

export const SecureJournalContainer: React.FC = () => {
  const [plaintext, setPlaintext] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [status, setStatus] = useState('Awaiting passphrase');
  const [keyMaterial, setKeyMaterial] = useState<string | null>(null);
  const session = useAppStore((state) => state.session);

  const userSalt = session?.user_id ? `journal:${session.user_id}:v1` : '';

  useEffect(() => {
    let isMounted = true;
    if (passphrase.length >= 8 && userSalt) {
      deriveIsolationKey(passphrase, userSalt).then(k => {
        if (isMounted) {
          setKeyMaterial(k);
          setStatus("Isolation Key Derived Successfully");
        }
      });
    } else {
      setStatus("Awaiting valid passphrase (min 8 chars)");
      setKeyMaterial(null);
    }
    return () => { isMounted = false; };
  }, [passphrase, userSalt]);

  const handleSave = async () => {
    if (keyMaterial && plaintext) {
      const encrypted: EncryptedPayload = await encryptJournalData(plaintext, keyMaterial);
      if (!session) {
        setStatus('Sign in before saving encrypted journal entries.');
        return;
      }
      await apiRequest('/api/v1/journal_entries', session.token, {
        method: 'POST',
        body: JSON.stringify({ ...encrypted, salt_id: userSalt, salt_version: 1 }),
      });
      setStatus(`Saved securely! IV: ${encrypted.iv.substring(0, 10)}...`);
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
        style={[styles.button, (!session || !keyMaterial || !plaintext) && styles.disabled]}
        onPress={() => void handleSave()}
        disabled={!session || !keyMaterial || !plaintext}
      >
        <Text style={styles.buttonText}>Encrypt & Save</Text>
      </TouchableOpacity>
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
  buttonText: { color: '#fff', fontWeight: 'bold' }
});
