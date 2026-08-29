import React, { useEffect } from 'react';
import { HomeScreen } from './src/screens/HomeScreen';
import { useAppStore } from './src/lib/store';

export default function App() {
  const bootstrapSession = useAppStore((state) => state.bootstrapSession);

  useEffect(() => {
    void bootstrapSession();
  }, [bootstrapSession]);

  return <HomeScreen />;
}
