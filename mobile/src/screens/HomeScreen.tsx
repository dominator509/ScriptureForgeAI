import React, { useEffect, useState } from 'react';
import { ScrollView, View, Text, TextInput, TouchableOpacity, StyleSheet } from 'react-native';
import { SecureJournalContainer } from '../components/SecureJournalContainer';
import { createRoom, getRoomState, listActiveRooms, loginAccount, logoutSession, registerAccount, roomStreamProtocols, roomStreamUrl, RoomEvent } from '../lib/api';
import { useAppStore } from '../lib/store';

export const HomeScreen: React.FC = () => {
  const session = useAppStore((state) => state.session);
  const setSession = useAppStore((state) => state.setSession);
  const rooms = useAppStore((state) => state.rooms);
  const setRooms = useAppStore((state) => state.setRooms);
  const activeRoomId = useAppStore((state) => state.activeRoomId);
  const setActiveRoom = useAppStore((state) => state.setActiveRoom);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [organizationId, setOrganizationId] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [roomTitle, setRoomTitle] = useState('');
  const [status, setStatus] = useState('Sign in or register to sync rooms and journals.');
  const [streamStatus, setStreamStatus] = useState('No room selected.');
  const [latestEvent, setLatestEvent] = useState<RoomEvent | null>(null);

  const syncRooms = async (token: string) => {
    const nextRooms = await listActiveRooms(token);
    setRooms(nextRooms);
    if (!activeRoomId && nextRooms.length > 0) {
      setActiveRoom(nextRooms[0].id);
    }
  };

  const handleLogin = async () => {
    try {
      const nextSession = await loginAccount(email, password, organizationId, mfaCode || undefined);
      if (nextSession.requires_mfa) {
        setSession(null);
        setRooms([]);
        setStatus('MFA code required for this account.');
        return;
      }
      setSession(nextSession);
      await syncRooms(nextSession.token);
      setStatus('Signed in.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Login failed.');
    }
  };

  const handleRegister = async () => {
    try {
      const nextSession = await registerAccount(email, password, organizationId);
      setSession(nextSession);
      await syncRooms(nextSession.token);
      setStatus('Registered and signed in.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Registration failed.');
    }
  };

  const handleCreateRoom = async () => {
    if (!session || !roomTitle.trim()) return;
    try {
      const room = await createRoom(session.token, roomTitle.trim());
      const nextRooms = [room, ...rooms.filter((candidate) => candidate.id !== room.id)];
      setRooms(nextRooms);
      setActiveRoom(room.id);
      setRoomTitle('');
      setStatus('Room created.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Room creation failed.');
    }
  };

  const handleRefreshRooms = async () => {
    if (!session) return;
    try {
      await syncRooms(session.token);
      setStatus('Rooms refreshed.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Room refresh failed.');
    }
  };

  const handleLogout = async () => {
    if (!session) return;
    const activeSession = session;
    setSession(null);
    setRooms([]);
    try {
      await logoutSession(activeSession.token, activeSession.refresh_token, activeSession.organization_id);
      setStatus('Signed out.');
    } catch (error) {
      setStatus(error instanceof Error ? error.message : 'Logout failed.');
    }
  };

  useEffect(() => {
    if (!session || !activeRoomId) {
      setStreamStatus('Sign in and select a room.');
      setLatestEvent(null);
      return undefined;
    }

    let disposed = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let reconnectAttempt = 0;

    const stopPolling = () => {
      if (pollTimer !== null) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const applyEvent = (event: RoomEvent) => {
      if (disposed || event.room_id !== activeRoomId || !Number.isFinite(event.sequence)) return;
      setLatestEvent(event);
      setStreamStatus(`Room sequence ${event.sequence}`);
    };

    const pollState = async () => {
      try {
        const event = await getRoomState(session.token, activeRoomId);
        if (event.sequence > 0) applyEvent(event);
      } catch {
        if (!disposed) setStreamStatus('Room stream and polling fallback unavailable.');
      }
    };

    const startPolling = () => {
      if (pollTimer !== null) return;
      setStreamStatus('WebSocket unavailable; using polling fallback.');
      void pollState();
      pollTimer = setInterval(() => void pollState(), 5000);
    };

    const connect = () => {
      if (disposed) return;
      setStreamStatus('Connecting to room stream.');
      socket = new WebSocket(roomStreamUrl(activeRoomId), roomStreamProtocols(session.token));
      socket.onopen = () => {
        reconnectAttempt = 0;
        stopPolling();
        setStreamStatus('Room stream connected.');
        socket?.send(JSON.stringify({ type: 'presence', room_id: activeRoomId, sequence: 0, payload: { status: 'joined' } }));
      };
      socket.onmessage = (event) => {
        try {
          applyEvent(JSON.parse(event.data) as RoomEvent);
        } catch {
          setStreamStatus('Room stream sent an invalid event.');
        }
      };
      socket.onerror = () => {
        if (!disposed) setStreamStatus('Room stream failed; retrying.');
      };
      socket.onclose = () => {
        socket = null;
        if (disposed) return;
        startPolling();
        const delay = Math.min(1000 * 2 ** reconnectAttempt, 10000);
        reconnectAttempt = Math.min(reconnectAttempt + 1, 4);
        reconnectTimer = setTimeout(connect, delay);
      };
    };

    connect();
    return () => {
      disposed = true;
      stopPolling();
      if (reconnectTimer !== null) clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [activeRoomId, session?.token]);

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>ScriptureForge AI Mobile</Text>
        <Text style={styles.headerSubtitle}>{session ? session.organization_id : 'Authenticated workspace'}</Text>
      </View>

      <View style={styles.panel}>
        <Text style={styles.panelTitle}>Account</Text>
        <TextInput style={styles.input} placeholder="Organization ID" value={organizationId} onChangeText={setOrganizationId} autoCapitalize="none" />
        <TextInput style={styles.input} placeholder="Email" value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" />
        <TextInput style={styles.input} placeholder="Password" value={password} onChangeText={setPassword} secureTextEntry />
        <TextInput style={styles.input} placeholder="MFA code" value={mfaCode} onChangeText={setMfaCode} keyboardType="number-pad" />
        <View style={styles.row}>
          <TouchableOpacity style={styles.button} onPress={() => void handleLogin()}>
            <Text style={styles.buttonText}>Login</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.secondaryButton} onPress={() => void handleRegister()}>
            <Text style={styles.secondaryButtonText}>Register</Text>
          </TouchableOpacity>
        </View>
        {session && (
          <TouchableOpacity style={styles.secondaryButton} onPress={() => void handleLogout()}>
            <Text style={styles.secondaryButtonText}>Logout</Text>
          </TouchableOpacity>
        )}
        <Text style={styles.status}>{status}</Text>
      </View>

      <View style={styles.panel}>
        <View style={styles.panelHeader}>
          <Text style={styles.panelTitle}>Rooms</Text>
          <TouchableOpacity onPress={() => void handleRefreshRooms()} disabled={!session}>
            <Text style={[styles.link, !session && styles.disabledText]}>Refresh</Text>
          </TouchableOpacity>
        </View>
        <View style={styles.row}>
          <TextInput style={[styles.input, styles.roomInput]} placeholder="Room title" value={roomTitle} onChangeText={setRoomTitle} />
          <TouchableOpacity style={[styles.button, (!session || !roomTitle.trim()) && styles.disabled]} onPress={() => void handleCreateRoom()} disabled={!session || !roomTitle.trim()}>
            <Text style={styles.buttonText}>Create</Text>
          </TouchableOpacity>
        </View>
        {rooms.length === 0 ? (
          <Text style={styles.empty}>No active rooms loaded.</Text>
        ) : (
          rooms.map((room) => (
            <TouchableOpacity key={room.id} style={[styles.room, activeRoomId === room.id && styles.activeRoom]} onPress={() => setActiveRoom(room.id)}>
              <Text style={styles.roomTitle}>{room.title}</Text>
              <Text style={styles.roomMeta}>{room.id}</Text>
            </TouchableOpacity>
          ))
        )}
        <Text style={styles.streamStatus}>{streamStatus}</Text>
        {latestEvent && <Text style={styles.roomMeta}>Latest event: {latestEvent.type} #{latestEvent.sequence}</Text>}
      </View>

      <SecureJournalContainer />
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#F9FAFB' },
  content: { paddingBottom: 24 },
  header: { backgroundColor: '#fff', padding: 16, paddingTop: 40, borderBottomWidth: 1, borderBottomColor: '#E5E7EB' },
  headerTitle: { fontSize: 20, fontWeight: 'bold', color: '#312E81' },
  headerSubtitle: { marginTop: 4, color: '#6B7280' },
  panel: { backgroundColor: '#fff', borderRadius: 8, margin: 16, marginBottom: 0, padding: 16, elevation: 2 },
  panelHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  panelTitle: { fontSize: 18, fontWeight: '700', color: '#111827', marginBottom: 12 },
  input: { borderWidth: 1, borderColor: '#D1D5DB', borderRadius: 6, padding: 10, marginBottom: 8 },
  roomInput: { flex: 1, marginBottom: 0, marginRight: 8 },
  row: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  button: { backgroundColor: '#4F46E5', padding: 12, borderRadius: 6, alignItems: 'center' },
  secondaryButton: { backgroundColor: '#EEF2FF', padding: 12, borderRadius: 6, alignItems: 'center' },
  buttonText: { color: '#fff', fontWeight: '700' },
  secondaryButtonText: { color: '#3730A3', fontWeight: '700' },
  status: { marginTop: 12, color: '#2563EB', fontSize: 12 },
  streamStatus: { marginTop: 12, color: '#047857', fontSize: 12 },
  link: { color: '#2563EB', fontWeight: '700' },
  disabled: { opacity: 0.5 },
  disabledText: { color: '#9CA3AF' },
  empty: { color: '#6B7280' },
  room: { borderWidth: 1, borderColor: '#E5E7EB', borderRadius: 6, padding: 10, marginTop: 8 },
  activeRoom: { borderColor: '#4F46E5', backgroundColor: '#EEF2FF' },
  roomTitle: { color: '#111827', fontWeight: '700' },
  roomMeta: { color: '#6B7280', fontSize: 11, marginTop: 2 },
});
