import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';

interface ScriptureReaderProps {
  isOffline?: boolean;
}

export const ScriptureReader: React.FC<ScriptureReaderProps> = ({ isOffline = false }) => {
  return (
    <View style={{ backgroundColor: '#F9FAFB', flex: 1 }}>
      {/* Degraded State Banner */}
      {isOffline && (
        <View style={styles.offlineBanner} accessibilityRole="alert" accessibilityLiveRegion="polite">
            <Text style={styles.offlineText}>Live sync disconnected - Reconnecting (10s poll)...</Text>
        </View>
      )}

      <View style={{ padding: 20 }}>
          <Text style={{ color: '#111827', fontSize: 18, fontWeight: 'bold' }}>John 1:1</Text>
          <Text style={{ color: '#6B7280', fontSize: 16, marginTop: 10 }}>In the beginning was the Word...</Text>

          <TouchableOpacity
            accessibilityRole="button"
            accessibilityLabel="View Commentary for current verse"
            style={{ backgroundColor: '#2563EB', padding: 12, marginTop: 24, borderRadius: 6, alignItems: 'center' }}>
            <Text style={{ color: '#FFFFFF', fontWeight: '600' }}>View Commentary</Text>
          </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
    offlineBanner: {
        backgroundColor: '#FEF08A', // Yellow-200
        paddingVertical: 8,
        paddingHorizontal: 16,
        alignItems: 'center',
        justifyContent: 'center',
        borderBottomWidth: 1,
        borderBottomColor: '#FDE047',
    },
    offlineText: {
        color: '#854D0E', // Yellow-800 for high contrast
        fontSize: 14,
        fontWeight: '500',
    }
});
