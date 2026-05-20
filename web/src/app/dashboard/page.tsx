'use client';

import { JournalEditor } from '../../components/JournalEditor';
import { RoomLayout } from '../../components/layout/RoomLayout';

export default function Dashboard() {
  return (
    <div className="flex min-h-screen bg-gray-100">
      <div className="w-1/2 p-4 border-r">
        <RoomLayout />
      </div>
      <div className="w-1/2 p-4 overflow-y-auto">
        <JournalEditor />
      </div>
    </div>
  )
}
