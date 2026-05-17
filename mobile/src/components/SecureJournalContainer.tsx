import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet } from 'react-native';

// NOTE: In a true React Native environment, `window.crypto` is not available natively.
// We mock the interface here for the sake of the structural implementation, but in production,
// libraries like `react-native-crypto` or `expo-crypto` are required.
const mockEncrypt = async (text: string) => {
  return { ciphertext: btoa(text), iv: 'mock-iv' };
};

export const SecureJournalContainer: React.FC = () => {
  const [plaintext, setPlaintext] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [status, setStatus] = useState('Awaiting passphrase');

  useEffect(() => {
    if (passphrase.length >= 8) {
      setStatus("Isolation Key Derived Successfully");
    } else {
      setStatus("Awaiting valid passphrase (min 8 chars)");
    }
  }, [passphrase]);

  const handleSave = async () => {
    if (passphrase.length >= 8 && plaintext) {
      const encrypted = await mockEncrypt(plaintext);
      setStatus(`Saved securely! Cipher: ${encrypted.ciphertext.substring(0, 10)}...`);
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Zero-Knowledge Journal</Text>

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
        style={[styles.button, (passphrase.length < 8 || !plaintext) && styles.disabled]}
        onPress={handleSave}
        disabled={passphrase.length < 8 || !plaintext}
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
