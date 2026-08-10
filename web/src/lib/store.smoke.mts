import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';

const values = new Map<string, string>();
const localStorage = {
  clear: () => values.clear(),
  getItem: (key: string) => values.get(key) ?? null,
  removeItem: (key: string) => { values.delete(key); },
  setItem: (key: string, value: string) => { values.set(key, value); },
};
const originalFetch = globalThis.fetch;

Object.defineProperty(globalThis, 'window', {
  configurable: true,
  value: { localStorage },
});

const { bootstrapSession, useAppStore } = await import('./store.ts');

beforeEach(() => {
  useAppStore.getState().clearSession();
  values.clear();
  useAppStore.setState({ token: null, userId: null, organizationId: null, activeRoomId: null });
  globalThis.fetch = async () => new Response(JSON.stringify({ message: 'unexpected request' }), { status: 500 });
});

after(() => {
  globalThis.fetch = originalFetch;
  delete (globalThis as { window?: unknown }).window;
});

test('web session store keeps access and refresh tokens out of localStorage', () => {
  useAppStore.getState().setSession({
    token: 'access-token',
    refresh_token: 'refresh-token',
    user_id: 'user-1',
    organization_id: 'org-1',
  });

  assert.equal(useAppStore.getState().token, 'access-token');
  assert.equal(localStorage.getItem('auth_token'), null);
  assert.equal(localStorage.getItem('refresh_token'), null);
  assert.equal(localStorage.getItem('organization_id'), 'org-1');
});

test('web bootstrap single-flights cookie refresh into memory', async () => {
  values.set('user_id', 'user-1');
  values.set('organization_id', 'org-1');
  useAppStore.setState({ userId: 'user-1', organizationId: 'org-1' });
  const calls: RequestInit[] = [];
  globalThis.fetch = async (_input: RequestInfo | URL, init?: RequestInit) => {
    calls.push(init ?? {});
    return new Response(JSON.stringify({ token: 'fresh-token', user_id: 'user-1', organization_id: 'org-1' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  const first = bootstrapSession();
  const second = bootstrapSession();
  assert.strictEqual(first, second);
  await Promise.all([first, second]);

  assert.equal(calls.length, 1);
  assert.deepEqual(JSON.parse(String(calls[0]?.body)), { organization_id: 'org-1' });
  assert.equal(calls[0]?.credentials, 'include');
  assert.equal(new Headers(calls[0]?.headers).get('X-ScriptureForge-Client'), 'web');
  assert.equal(useAppStore.getState().token, 'fresh-token');
  assert.equal(localStorage.getItem('auth_token'), null);
});

test('web bootstrap clears stale local principal when cookie refresh is rejected', async () => {
  values.set('user_id', 'user-1');
  values.set('organization_id', 'org-1');
  useAppStore.setState({ userId: 'user-1', organizationId: 'org-1' });
  globalThis.fetch = async () => new Response(JSON.stringify({ message: 'expired' }), { status: 401 });

  await bootstrapSession();

  assert.equal(useAppStore.getState().token, null);
  assert.equal(useAppStore.getState().userId, null);
  assert.equal(useAppStore.getState().organizationId, null);
  assert.equal(localStorage.getItem('organization_id'), null);
});
