'use client';

import { useEffect } from 'react';
import { JournalEditor } from '../../components/JournalEditor';
import { AuthPanel } from '../../components/AuthPanel';
import { RoomLayout } from '../../components/layout/RoomLayout';
import { bootstrapSession } from '../../lib/store';

export default function Dashboard() {
  useEffect(() => {
    void bootstrapSession();
  }, []);

  return (
    <div className="flex min-h-screen bg-gray-100">
      <div className="w-1/2 p-4 border-r space-y-4">
        <AuthPanel />
        <RoomLayout />
      </div>
      <div className="w-1/2 p-4 overflow-y-auto">
        <JournalEditor />
      </div>
    </div>
  )
}
