import { create } from 'zustand'
import { AuthSession, configureSessionBridge } from './api'

if (typeof window !== 'undefined') window.localStorage.removeItem('refresh_token')

interface AppState {
  currentRole: string
  setRole: (role: string) => void
  activeRoomId: string | null
  setActiveRoom: (id: string | null) => void
  token: string | null
  refreshToken: string | null
  userId: string | null
  organizationId: string | null
  setSession: (session: AuthSession | null) => void
  clearSession: () => void
}

export const useAppStore = create<AppState>()((set) => ({
  currentRole: 'member',
  setRole: (role) => set({ currentRole: role }),
  activeRoomId: null,
  setActiveRoom: (id) => set({ activeRoomId: id }),
  token: typeof window === 'undefined' ? null : window.localStorage.getItem('auth_token'),
  refreshToken: null,
  userId: typeof window === 'undefined' ? null : window.localStorage.getItem('user_id'),
  organizationId: typeof window === 'undefined' ? null : window.localStorage.getItem('organization_id'),
  setSession: (session) => {
    if (!session) {
      window.localStorage.removeItem('auth_token')
      window.localStorage.removeItem('refresh_token')
      window.localStorage.removeItem('user_id')
      window.localStorage.removeItem('organization_id')
      set({ token: null, refreshToken: null, userId: null, organizationId: null, activeRoomId: null })
      return
    }
    window.localStorage.removeItem('refresh_token')
    window.localStorage.setItem('auth_token', session.token)
    window.localStorage.setItem('user_id', session.user_id)
    window.localStorage.setItem('organization_id', session.organization_id)
    set({ token: session.token, refreshToken: null, userId: session.user_id, organizationId: session.organization_id })
  },
  clearSession: () => {
    window.localStorage.removeItem('auth_token')
    window.localStorage.removeItem('refresh_token')
    window.localStorage.removeItem('user_id')
    window.localStorage.removeItem('organization_id')
    set({ token: null, refreshToken: null, userId: null, organizationId: null, activeRoomId: null })
  },
}))

configureSessionBridge({
  getSession: () => {
    const state = useAppStore.getState()
    if (!state.token || !state.userId || !state.organizationId) return null
    return {
      token: state.token,
      refresh_token: state.refreshToken ?? undefined,
      user_id: state.userId,
      organization_id: state.organizationId,
    }
  },
  onSessionChange: (session) => useAppStore.getState().setSession(session),
})
