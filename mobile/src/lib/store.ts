import { create } from 'zustand'

interface AppState {
  currentRole: string
  setRole: (role: string) => void
  activeRoomId: string | null
  setActiveRoom: (id: string | null) => void
}

export const useAppStore = create<AppState>()((set) => ({
  currentRole: 'member',
  setRole: (role) => set({ currentRole: role }),
  activeRoomId: null,
  setActiveRoom: (id) => set({ activeRoomId: id }),
}))
