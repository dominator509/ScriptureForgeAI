import React from 'react';
import { View, Text, TouchableOpacity } from 'react-native';

export const ScriptureReader = () => {
  return (
    <View style={{ backgroundColor: '#F9FAFB', padding: 20 }}>
      <Text style={{ color: '#111827', fontSize: 18 }}>John 1:1</Text>
      <Text style={{ color: '#6B7280', fontSize: 16 }}>In the beginning was the Word...</Text>

      <TouchableOpacity style={{ backgroundColor: '#2563EB', padding: 10, marginTop: 20 }}>
        <Text style={{ color: '#FFFFFF' }}>View Commentary</Text>
      </TouchableOpacity>
    </View>
  );
};
