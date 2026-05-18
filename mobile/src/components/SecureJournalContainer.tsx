import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet } from 'react-native';
import { deriveIsolationKey, encryptJournalData, EncryptedPayload } from '../lib/crypto';

export const SecureJournalContainer: React.FC = () => {
  const [plaintext, setPlaintext] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [status, setStatus] = useState('Awaiting passphrase');
  const [keyMaterial, setKeyMaterial] = useState<string | null>(null);

  const userSalt = "mobile-static-salt-123";

  useEffect(() => {
    let isMounted = true;
    if (passphrase.length >= 8) {
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
  }, [passphrase]);

  const handleSave = async () => {
    if (keyMaterial && plaintext) {
      const encrypted: EncryptedPayload = await encryptJournalData(plaintext, keyMaterial);
      setStatus(`Saved securely! IV: ${encrypted.iv.substring(0, 10)}...`);
      // In production, dispatch payload to API over HTTPS
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Zero-Knowledge Journal (Mobile)</Text>

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
        style={[styles.button, (!keyMaterial || !plaintext) && styles.disabled]}
        onPress={() => void handleSave()}
        disabled={!keyMaterial || !plaintext}
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
  status: { fontSize: 12, color: '#2563EB', marginBottom: 16 },
  button: { backgroundColor: '#4F46E5', padding: 12, borderRadius: 6, alignItems: 'center' },
  disabled: { opacity: 0.5 },
  buttonText: { color: '#fff', fontWeight: 'bold' }
});
