import type { AuthSession } from './api'

const authSessionStorageKey = 'scriptureforge.auth.session.v1'

interface SecureStoreOptions {
  keychainAccessible?: number
}

export interface SecureStoreAdapter {
  getItemAsync: (key: string, options?: SecureStoreOptions) => Promise<string | null>
  setItemAsync: (key: string, value: string, options?: SecureStoreOptions) => Promise<void>
  deleteItemAsync: (key: string, options?: SecureStoreOptions) => Promise<void>
}

interface SecureStoreModule extends SecureStoreAdapter {
  AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY?: number
}

type StoredAuthSession = Pick<AuthSession, 'token' | 'refresh_token' | 'user_id' | 'organization_id'>

let adapterOverride: SecureStoreAdapter | null = null
let operationQueue: Promise<void> = Promise.resolve()

function secureStoreOptions(adapter: SecureStoreModule): SecureStoreOptions | undefined {
  if (typeof adapter.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY !== 'number') return undefined
  return { keychainAccessible: adapter.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY }
}

async function resolveSecureStore(): Promise<SecureStoreModule> {
  if (adapterOverride) return adapterOverride
  return require('expo-secure-store') as SecureStoreModule
}

function enqueue<T>(operation: (adapter: SecureStoreModule, options?: SecureStoreOptions) => Promise<T>): Promise<T> {
  const run = async (): Promise<T> => {
    const adapter = await resolveSecureStore()
    return operation(adapter, secureStoreOptions(adapter))
  }
  const next = operationQueue.then(run, run)
  operationQueue = next.then(() => undefined, () => undefined)
  return next
}

function storedSession(session: AuthSession | null): StoredAuthSession | null {
  if (!session?.token || !session.refresh_token || !session.user_id || !session.organization_id) return null
  return {
    token: session.token,
    refresh_token: session.refresh_token,
    user_id: session.user_id,
    organization_id: session.organization_id,
  }
}

function isStoredAuthSession(value: unknown): value is StoredAuthSession {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<StoredAuthSession>
  return [candidate.token, candidate.refresh_token, candidate.user_id, candidate.organization_id]
    .every((field) => typeof field === 'string' && field.length > 0)
}

export function persistAuthSession(session: AuthSession | null): Promise<void> {
  const value = storedSession(session)
  return enqueue(async (adapter, options) => {
    if (!value) {
      await adapter.deleteItemAsync(authSessionStorageKey, options)
      return
    }
    await adapter.setItemAsync(authSessionStorageKey, JSON.stringify(value), options)
  })
}

export function clearPersistedAuthSession(): Promise<void> {
  return persistAuthSession(null)
}

export function loadPersistedAuthSession(): Promise<StoredAuthSession | null> {
  return enqueue(async (adapter, options) => {
    let raw: string | null
    try {
      raw = await adapter.getItemAsync(authSessionStorageKey, options)
    } catch {
      return null
    }
    if (!raw) return null

    try {
      const parsed: unknown = JSON.parse(raw)
      if (isStoredAuthSession(parsed)) return parsed
    } catch {
      // Invalid local state is cleared below so startup cannot reuse it.
    }
    try {
      await adapter.deleteItemAsync(authSessionStorageKey, options)
    } catch {
      // A subsequent authenticated login can replace unreadable local state.
    }
    return null
  })
}

// Tests inject a memory adapter so the smoke gate never needs a native runtime.
export function setSecureStoreAdapterForTesting(adapter: SecureStoreAdapter | null): void {
  adapterOverride = adapter
}
