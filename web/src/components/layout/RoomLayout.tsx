import React, { useEffect, useState } from 'react';
import { createRoom as createRoomRequest, getRoomState, listRooms, RoomEvent, RoomSummary, roomStreamUrl } from '../../lib/api';
import { useAppStore } from '../../lib/store';

export const RoomLayout: React.FC = () => {
  const { currentRole, activeRoomId, setActiveRoom, token } = useAppStore();
  const [rooms, setRooms] = useState<RoomSummary[]>([]);
  const [title, setTitle] = useState('Bible Study Room');
  const [status, setStatus] = useState('');
  const [streamStatus, setStreamStatus] = useState('No room selected');
  const [latestEvent, setLatestEvent] = useState<RoomEvent | null>(null);

  const loadRooms = async () => {
    if (!token) return;
    try {
      setRooms(await listRooms(token));
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to load rooms');
    }
  };

  const createRoom = async () => {
    if (!token) return;
    try {
      const room = await createRoomRequest(token, title);
      setRooms((current) => [room, ...current]);
      setActiveRoom(room.id);
      setStatus('Room created');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to create room');
    }
  };

  useEffect(() => {
    void loadRooms();
  }, [token]);

  useEffect(() => {
    if (!activeRoomId || !token) {
      setStreamStatus('Sign in and select a room');
      setLatestEvent(null);
      return undefined;
    }

    let disposed = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let pollTimer: number | null = null;
    let reconnectAttempt = 0;

    const stopPolling = () => {
      if (pollTimer !== null) {
        window.clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const applyEvent = (event: RoomEvent) => {
      if (disposed || event.room_id !== activeRoomId || !Number.isFinite(event.sequence)) return;
      setLatestEvent(event);
      setStreamStatus(`Live stream connected at sequence ${event.sequence}`);
    };

    const pollState = async () => {
      try {
        const event = await getRoomState(token, activeRoomId);
        if (event.sequence > 0) applyEvent(event);
      } catch {
        if (!disposed) setStreamStatus('Room stream and polling fallback unavailable');
      }
    };

    const startPolling = () => {
      if (pollTimer !== null) return;
      setStreamStatus('WebSocket unavailable; using polling fallback');
      void pollState();
      pollTimer = window.setInterval(() => void pollState(), 5000);
    };

    const connect = () => {
      if (disposed) return;
      setStreamStatus('Connecting to room stream');
      socket = new WebSocket(roomStreamUrl(activeRoomId, token));
      socket.onopen = () => {
        reconnectAttempt = 0;
        stopPolling();
        setStreamStatus('Room stream connected');
        socket?.send(JSON.stringify({ type: 'presence', room_id: activeRoomId, sequence: 0, payload: { status: 'joined' } }));
      };
      socket.onmessage = (event) => {
        try {
          applyEvent(JSON.parse(event.data) as RoomEvent);
        } catch {
          setStreamStatus('Room stream sent an invalid event');
        }
      };
      socket.onerror = () => {
        if (!disposed) setStreamStatus('Room stream failed; retrying');
      };
      socket.onclose = () => {
        socket = null;
        if (disposed) return;
        startPolling();
        const delay = Math.min(1000 * 2 ** reconnectAttempt, 10000);
        reconnectAttempt = Math.min(reconnectAttempt + 1, 4);
        reconnectTimer = window.setTimeout(connect, delay);
      };
    };

    connect();
    return () => {
      disposed = true;
      stopPolling();
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [activeRoomId, token]);

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      <header className="bg-white shadow p-4 flex justify-between items-center">
        <h1 className="text-xl font-bold">ScriptureForge Live Room</h1>
        <span className="text-sm bg-blue-100 text-blue-800 px-2 py-1 rounded">Role: {currentRole}</span>
      </header>
      <main className="flex-grow p-4">
        {!token && <div className="text-red-600 text-sm">Sign in to create or join rooms.</div>}
        {token && (
          <div className="mb-4 flex gap-2">
            <input className="border rounded p-2 flex-1" value={title} onChange={(event) => setTitle(event.target.value)} />
            <button className="px-3 py-2 bg-indigo-600 text-white rounded" onClick={() => void createRoom()}>Create</button>
          </div>
        )}
        {rooms.length > 0 && (
          <div className="mb-4 flex flex-wrap gap-2">
            {rooms.map((room) => (
              <button key={room.id} className="px-3 py-2 border rounded" onClick={() => setActiveRoom(room.id)}>
                {room.title}
              </button>
            ))}
          </div>
        )}
        {activeRoomId ? (
          <div className="bg-white p-6 rounded shadow">
            <h2 className="text-lg mb-4">Active Session: {activeRoomId}</h2>
            <p className="text-xs text-gray-500 mb-4">{streamStatus}</p>
            {latestEvent && <p className="text-xs text-gray-600 mb-4">Latest event: {latestEvent.type} #{latestEvent.sequence}</p>}
            {currentRole === 'admin' ? (
              <p>You have presenter controls.</p>
            ) : (
              <p>You are viewing the live synchronized presentation.</p>
            )}
          </div>
        ) : (
          <div className="text-gray-500 text-center mt-10">No active room selected.</div>
        )}
        {status && <div className="mt-3 text-xs text-blue-700">{status}</div>}
      </main>
    </div>
  );
};
