import { create } from 'zustand'

interface AppState {
  currentRole: string
  setRole: (role: string) => void
  activeRoomId: string | null
  setActiveRoom: (id: string | null) => void
  token: string | null
  refreshToken: string | null
  userId: string | null
  setSession: (token: string, refreshToken: string, userId: string) => void
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
  setSession: (token, refreshToken, userId) => {
    window.localStorage.setItem('auth_token', token)
    window.localStorage.setItem('refresh_token', refreshToken)
    window.localStorage.setItem('user_id', userId)
    set({ token, refreshToken, userId })
  },
  clearSession: () => {
    window.localStorage.removeItem('auth_token')
    window.localStorage.removeItem('refresh_token')
    window.localStorage.removeItem('user_id')
    set({ token: null, refreshToken: null, userId: null, activeRoomId: null })
  },
}))
