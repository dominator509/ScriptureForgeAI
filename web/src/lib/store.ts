import { create } from 'zustand'
import { type AuthSession, configureSessionBridge, refreshSession } from './api.ts'

if (typeof window !== 'undefined') {
  window.localStorage.removeItem('auth_token')
  window.localStorage.removeItem('refresh_token')
}

interface AppState {
  currentRole: string
  setRole: (role: string) => void
  activeRoomId: string | null
  setActiveRoom: (id: string | null) => void
  token: string | null
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
  token: null,
  userId: typeof window === 'undefined' ? null : window.localStorage.getItem('user_id'),
  organizationId: typeof window === 'undefined' ? null : window.localStorage.getItem('organization_id'),
  setSession: (session) => {
    if (!session || !session.token || session.requires_mfa) {
      window.localStorage.removeItem('auth_token')
      window.localStorage.removeItem('refresh_token')
      window.localStorage.removeItem('user_id')
      window.localStorage.removeItem('organization_id')
      set({ token: null, userId: null, organizationId: null, activeRoomId: null })
      return
    }
    window.localStorage.removeItem('refresh_token')
    window.localStorage.setItem('user_id', session.user_id)
    window.localStorage.setItem('organization_id', session.organization_id)
    set({ token: session.token, userId: session.user_id, organizationId: session.organization_id })
  },
  clearSession: () => {
    window.localStorage.removeItem('auth_token')
    window.localStorage.removeItem('refresh_token')
    window.localStorage.removeItem('user_id')
    window.localStorage.removeItem('organization_id')
    set({ token: null, userId: null, organizationId: null, activeRoomId: null })
  },
}))

let bootstrapInFlight: Promise<void> | null = null

export function bootstrapSession(): Promise<void> {
  if (typeof window === 'undefined') return Promise.resolve()
  const current = useAppStore.getState()
  if (current.token || !current.organizationId) return Promise.resolve()
  const organizationId = current.organizationId
  if (!bootstrapInFlight) {
    bootstrapInFlight = refreshSession(null, organizationId)
      .then((session) => {
        const latest = useAppStore.getState()
        if (!latest.token && latest.organizationId === organizationId) latest.setSession(session)
      })
      .catch(() => {
        const latest = useAppStore.getState()
        if (!latest.token && latest.organizationId === organizationId) latest.clearSession()
      })
      .finally(() => {
        bootstrapInFlight = null
      })
  }
  return bootstrapInFlight
}

configureSessionBridge({
  getSession: () => {
    const state = useAppStore.getState()
    if (!state.token || !state.userId || !state.organizationId) return null
    return {
      token: state.token,
      user_id: state.userId,
      organization_id: state.organizationId,
    }
  },
  onSessionChange: (session) => useAppStore.getState().setSession(session),
})
