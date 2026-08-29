import assert from 'node:assert/strict';
import { after, afterEach, beforeEach, test } from 'node:test';
import type { AuthSession } from './api.ts';
import type { SecureStoreAdapter } from './session-storage.ts';
import {
  clearPersistedAuthSession,
  loadPersistedAuthSession,
  persistAuthSession,
  setSecureStoreAdapterForTesting,
} from './session-storage.ts';
import { useAppStore } from './store.ts';

let storedValue: string | null = null;
let deleteCalls = 0;
const defaultFetch = globalThis.fetch;

const adapter: SecureStoreAdapter = {
  getItemAsync: async () => storedValue,
  setItemAsync: async (_key, value) => {
    storedValue = value;
  },
  deleteItemAsync: async () => {
    deleteCalls += 1;
    storedValue = null;
  },
};

const session: AuthSession = {
  token: 'access-token',
  refresh_token: 'refresh-token',
  user_id: 'user-1',
  organization_id: 'org-1',
  mfa_enrollment_token: 'must-not-persist',
};

beforeEach(() => {
  storedValue = null;
  deleteCalls = 0;
  setSecureStoreAdapterForTesting(adapter);
  useAppStore.setState({ session: null, sessionHydrated: false, activeRoomId: null, rooms: [] });
});

afterEach(() => {
  globalThis.fetch = defaultFetch;
});

test('mobile sessions persist in the secure adapter without MFA enrollment material', async () => {
  await persistAuthSession(session);
  assert.deepEqual(JSON.parse(storedValue!), {
    token: 'access-token',
    refresh_token: 'refresh-token',
    user_id: 'user-1',
    organization_id: 'org-1',
  });
  assert.deepEqual(await loadPersistedAuthSession(), {
    token: 'access-token',
    refresh_token: 'refresh-token',
    user_id: 'user-1',
    organization_id: 'org-1',
  });
});

test('mobile session persistence serializes writes so logout cannot be overwritten by an earlier login write', async () => {
  await Promise.all([persistAuthSession(session), clearPersistedAuthSession()]);
  assert.equal(storedValue, null);
  assert.equal(deleteCalls, 1);
});

test('invalid mobile session state is discarded before refresh bootstrap', async () => {
  storedValue = JSON.stringify({ token: 'access-token', refresh_token: '' });
  assert.equal(await loadPersistedAuthSession(), null);
  assert.equal(storedValue, null);
  assert.equal(deleteCalls, 1);
});

test('mobile app bootstrap refreshes a persisted session before marking the store ready', async () => {
  storedValue = JSON.stringify({
    token: 'expired-access-token',
    refresh_token: 'refresh-token',
    user_id: 'user-1',
    organization_id: 'org-1',
  });
  let refreshCalls = 0;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    refreshCalls += 1;
    assert.match(String(input), /\/api\/v1\/auth\/refresh$/);
    assert.equal(new Headers(init?.headers).get('Authorization'), null);
    assert.deepEqual(JSON.parse(String(init?.body)), {
      refresh_token: 'refresh-token',
      organization_id: 'org-1',
    });
    return new Response(JSON.stringify({
      token: 'fresh-access-token',
      refresh_token: 'rotated-refresh-token',
      user_id: 'user-1',
      organization_id: 'org-1',
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };

  await useAppStore.getState().bootstrapSession();
  assert.equal(refreshCalls, 1);
  assert.equal(useAppStore.getState().session?.token, 'fresh-access-token');
  assert.equal(useAppStore.getState().sessionHydrated, true);
  await loadPersistedAuthSession();
  assert.match(storedValue!, /fresh-access-token/);
  assert.match(storedValue!, /rotated-refresh-token/);
});

test('mobile app bootstrap clears a rejected persisted session', async () => {
  storedValue = JSON.stringify({
    token: 'expired-access-token',
    refresh_token: 'revoked-refresh-token',
    user_id: 'user-1',
    organization_id: 'org-1',
  });
  globalThis.fetch = async (): Promise<Response> => new Response('revoked', { status: 401 });

  await useAppStore.getState().bootstrapSession();
  assert.equal(useAppStore.getState().session, null);
  assert.equal(useAppStore.getState().sessionHydrated, true);
  await loadPersistedAuthSession();
  assert.equal(storedValue, null);
  assert.equal(deleteCalls, 1);
});

after(() => {
  setSecureStoreAdapterForTesting(null);
  console.log('mobile session storage smoke proof: mobile_session_secure_storage=true');
});
