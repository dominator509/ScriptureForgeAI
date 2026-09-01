import { create } from 'zustand'
import { configureSessionBridge, refreshSession } from './api.ts'
import type { AuthSession, RoomSummary } from './api.ts'
import { loadPersistedAuthSession, persistAuthSession } from './session-storage.ts'

function normalizeRole(role: string | undefined): string {
  return role?.trim().toLowerCase() || 'member'
}

interface AppState {
  currentRole: string
  setRole: (role: string) => void
  activeRoomId: string | null
  setActiveRoom: (id: string | null) => void
  session: AuthSession | null
  sessionHydrated: boolean
  bootstrapSession: () => Promise<void>
  setSession: (session: AuthSession | null) => void
  rooms: RoomSummary[]
  setRooms: (rooms: RoomSummary[]) => void
}

let bootstrapInFlight: Promise<void> | null = null

export const useAppStore = create<AppState>()((set, get) => ({
  currentRole: 'member',
  setRole: (role) => set({ currentRole: normalizeRole(role) }),
  activeRoomId: null,
  setActiveRoom: (id) => set({ activeRoomId: id }),
  session: null,
  sessionHydrated: false,
  bootstrapSession: async () => {
    if (get().sessionHydrated) return
    if (bootstrapInFlight) return bootstrapInFlight

    const run = (async () => {
      const persisted = await loadPersistedAuthSession()
      if (persisted) {
        try {
          const refreshed = await refreshSession(persisted.refresh_token, persisted.organization_id)
          get().setSession(refreshed)
        } catch {
          get().setSession(null)
        }
      }
      set({ sessionHydrated: true })
    })().catch(() => {
      get().setSession(null)
      set({ sessionHydrated: true })
    })

    bootstrapInFlight = run
    try {
      await run
    } finally {
      if (bootstrapInFlight === run) bootstrapInFlight = null
    }
  },
  setSession: (session) => {
    set((state) => {
      const sameWorkspace = Boolean(
        session && state.session
          && session.user_id === state.session.user_id
          && session.organization_id === state.session.organization_id,
      )
      return {
        session,
        currentRole: normalizeRole(session?.role),
        activeRoomId: sameWorkspace ? state.activeRoomId : null,
        rooms: sameWorkspace ? state.rooms : [],
      }
    })
    void persistAuthSession(session).catch(() => undefined)
  },
  rooms: [],
  setRooms: (rooms) => set({ rooms }),
}))

configureSessionBridge({
  getSession: () => useAppStore.getState().session,
  onSessionChange: (session) => useAppStore.getState().setSession(session),
})
