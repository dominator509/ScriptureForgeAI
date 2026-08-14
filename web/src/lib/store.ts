import { create } from 'zustand'

interface AppState {
  currentRole: string
  setRole: (role: string) => void
  activeRoomId: string | null
  setActiveRoom: (id: string | null) => void
  token: string | null
  refreshToken: string | null
  userId: string | null
  organizationId: string | null
  setSession: (token: string, refreshToken: string, userId: string, organizationId: string) => void
  clearSession: () => void
}

export const useAppStore = create<AppState>()((set) => ({
  currentRole: 'member',
  setRole: (role) => set({ currentRole: role }),
  activeRoomId: null,
  setActiveRoom: (id) => set({ activeRoomId: id }),
  token: typeof window === 'undefined' ? null : window.localStorage.getItem('auth_token'),
  refreshToken: typeof window === 'undefined' ? null : window.localStorage.getItem('refresh_token'),
  userId: typeof window === 'undefined' ? null : window.localStorage.getItem('user_id'),
  organizationId: typeof window === 'undefined' ? null : window.localStorage.getItem('organization_id'),
  setSession: (token, refreshToken, userId, organizationId) => {
    window.localStorage.setItem('auth_token', token)
    window.localStorage.setItem('refresh_token', refreshToken)
    window.localStorage.setItem('user_id', userId)
    window.localStorage.setItem('organization_id', organizationId)
    set({ token, refreshToken, userId, organizationId })
  },
  clearSession: () => {
    window.localStorage.removeItem('auth_token')
    window.localStorage.removeItem('refresh_token')
    window.localStorage.removeItem('user_id')
    window.localStorage.removeItem('organization_id')
    set({ token: null, refreshToken: null, userId: null, organizationId: null, activeRoomId: null })
  },
}))
