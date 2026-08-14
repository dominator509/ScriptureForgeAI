import { create } from 'zustand'
import { AuthSession, RoomSummary } from './api'

interface AppState {
  currentRole: string
  setRole: (role: string) => void
  activeRoomId: string | null
  setActiveRoom: (id: string | null) => void
  session: AuthSession | null
  setSession: (session: AuthSession | null) => void
  rooms: RoomSummary[]
  setRooms: (rooms: RoomSummary[]) => void
}

export const useAppStore = create<AppState>()((set) => ({
  currentRole: 'member',
  setRole: (role) => set({ currentRole: role }),
  activeRoomId: null,
  setActiveRoom: (id) => set({ activeRoomId: id }),
  session: null,
  setSession: (session) => set({ session, activeRoomId: null, rooms: [] }),
  rooms: [],
  setRooms: (rooms) => set({ rooms }),
}))
