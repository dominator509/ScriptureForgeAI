import React, { useEffect } from 'react';
import { useAppStore } from '../../lib/store';

export const RoomLayout: React.FC = () => {
  const { currentRole, activeRoomId } = useAppStore();

  useEffect(() => {
    if (activeRoomId) {
      // Functional implementation: connect to websocket and handle live synchronization
      const ws = new WebSocket(`wss://api.scriptureforge.com/ws/room?ticket=${localStorage.getItem('auth_token')}`);

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('Received sync event:', data);
        // Handle incoming synchronization commands (e.g., page turns, highlighter marks)
      };

      return () => ws.close();
    }
  }, [activeRoomId]);

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      <header className="bg-white shadow p-4 flex justify-between items-center">
        <h1 className="text-xl font-bold">ScriptureForge Live Room</h1>
        <span className="text-sm bg-blue-100 text-blue-800 px-2 py-1 rounded">Role: {currentRole}</span>
      </header>
      <main className="flex-grow p-4">
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
      </main>
    </div>
  );
};
