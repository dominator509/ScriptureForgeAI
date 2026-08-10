import { create } from 'zustand'
import { AuthSession, configureSessionBridge, RoomSummary } from './api'

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
  setSession: (session) => set((state) => {
    const sameWorkspace = Boolean(
      session && state.session
        && session.user_id === state.session.user_id
        && session.organization_id === state.session.organization_id,
    )
    return {
      session,
      activeRoomId: sameWorkspace ? state.activeRoomId : null,
      rooms: sameWorkspace ? state.rooms : [],
    }
  }),
  rooms: [],
  setRooms: (rooms) => set({ rooms }),
}))

configureSessionBridge({
  getSession: () => useAppStore.getState().session,
  onSessionChange: (session) => useAppStore.getState().setSession(session),
})
