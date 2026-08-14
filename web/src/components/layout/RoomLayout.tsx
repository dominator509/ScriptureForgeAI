import React, { useEffect, useState } from 'react';
import { apiRequest, WS_BASE_URL } from '../../lib/api';
import { useAppStore } from '../../lib/store';

interface RoomSummary {
  id: string;
  title: string;
  is_active: boolean;
}

export const RoomLayout: React.FC = () => {
  const { currentRole, activeRoomId, setActiveRoom, token } = useAppStore();
  const [rooms, setRooms] = useState<RoomSummary[]>([]);
  const [title, setTitle] = useState('Bible Study Room');
  const [status, setStatus] = useState('');

  const loadRooms = async () => {
    if (!token) return;
    try {
      setRooms(await apiRequest<RoomSummary[]>('/api/v1/rooms/active', token));
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Failed to load rooms');
    }
  };

  const createRoom = async () => {
    if (!token) return;
    try {
      const room = await apiRequest<RoomSummary>('/api/v1/rooms/create', token, {
        method: 'POST',
        body: JSON.stringify({ title }),
      });
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
    if (activeRoomId && token) {
      const ws = new WebSocket(`${WS_BASE_URL}/api/v1/rooms/stream/${activeRoomId}?ticket=${token}`);

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        setStatus(`Received ${data.type ?? 'room'} event`);
      };
      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'presence', room_id: activeRoomId, sequence: 0, payload: { status: 'joined' } }));
      };
      ws.onerror = () => setStatus('Room stream failed');

      return () => ws.close();
    }
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
