import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { SecureJournalContainer } from '../components/SecureJournalContainer';

export const HomeScreen: React.FC = () => {
  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>ScriptureForge AI Mobile</Text>
      </View>
      <SecureJournalContainer />
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#F9FAFB' },
  header: { backgroundColor: '#fff', padding: 16, paddingTop: 40, borderBottomWidth: 1, borderBottomColor: '#E5E7EB' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#312E81' },
});
