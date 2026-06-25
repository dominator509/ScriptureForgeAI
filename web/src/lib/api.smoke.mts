import assert from 'node:assert/strict';
import { beforeEach, test } from 'node:test';
import {
  API_BASE_URL,
  createRoom,
  getJournalEntry,
  getJournalBootstrap,
  listJournalEntries,
  listRooms,
  login,
  logout,
  refreshSession,
  register,
  roomStreamUrl,
  saveJournalEntry,
  WS_BASE_URL,
} from './api.ts';

type FetchCall = {
  url: string;
  init: RequestInit;
};

const calls: FetchCall[] = [];

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

beforeEach(() => {
  calls.length = 0;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push({ url, init: init ?? {} });

    if (url.endsWith('/api/v1/auth/register') || url.endsWith('/api/v1/auth/login') || url.endsWith('/api/v1/auth/refresh')) {
      return jsonResponse({
        token: 'access-token',
        refresh_token: 'refresh-token',
        user_id: 'user-1',
        organization_id: 'org-1',
      });
    }
    if (url.endsWith('/api/v1/auth/logout')) return new Response(null, { status: 204 });
    if (url.endsWith('/api/v1/journal/bootstrap')) {
      return jsonResponse({ salt_id: 'journal:v1:server-derived-salt', salt_version: 1 });
    }
    if (url.endsWith('/api/v1/journal_entries') && init?.method === 'POST') {
      return jsonResponse({ id: 'entry-1', ciphertext: 'ciphertext', iv: 'iv', salt_id: 'journal:v1:server-derived-salt', salt_version: 1 });
    }
    if (url.endsWith('/api/v1/journal_entries')) {
      return jsonResponse([{ id: 'entry-1', ciphertext: 'ciphertext', iv: 'iv', salt_id: 'journal:v1:server-derived-salt', salt_version: 1 }]);
    }
    if (url.endsWith('/api/v1/journal_entries/entry-1')) {
      return jsonResponse({ id: 'entry-1', ciphertext: 'ciphertext', iv: 'iv', salt_id: 'journal:v1:server-derived-salt', salt_version: 1 });
    }
    if (url.endsWith('/api/v1/rooms/active')) return jsonResponse([{ id: 'room-1', title: 'Study', is_active: true }]);
    if (url.endsWith('/api/v1/rooms/create')) return jsonResponse({ id: 'room-1', title: 'Study', is_active: true });

    return new Response('unexpected route', { status: 404 });
  };
});

test('auth helpers use canonical v1 routes and bearer logout revocation', async () => {
  const credentials = { email: 'reader@example.com', password: 'correct horse', organization_id: 'org-1' };

  assert.equal((await register(credentials)).token, 'access-token');
  assert.equal((await login(credentials)).refresh_token, 'refresh-token');
  assert.equal((await refreshSession('old-refresh')).organization_id, 'org-1');
  await logout('access-token', 'refresh-token');

  assert.deepEqual(
    calls.map((call) => [call.url, call.init.method ?? 'GET']),
    [
      [`${API_BASE_URL}/api/v1/auth/register`, 'POST'],
      [`${API_BASE_URL}/api/v1/auth/login`, 'POST'],
      [`${API_BASE_URL}/api/v1/auth/refresh`, 'POST'],
      [`${API_BASE_URL}/api/v1/auth/logout`, 'POST'],
    ],
  );
  assert.equal(new Headers(calls.at(-1)?.init.headers).get('Authorization'), 'Bearer access-token');
});

test('journal helpers list, save, and load encrypted payloads without plaintext fields', async () => {
  const bootstrap = await getJournalBootstrap('access-token');
  const payload = { ciphertext: 'ciphertext', iv: 'iv', salt_id: bootstrap.salt_id, salt_version: bootstrap.salt_version };

  assert.equal((await listJournalEntries('access-token'))[0]?.id, 'entry-1');
  assert.equal((await saveJournalEntry('access-token', payload)).id, 'entry-1');
  assert.equal((await getJournalEntry('access-token', 'entry-1')).ciphertext, 'ciphertext');

  const saveBody = JSON.parse(String(calls[2]?.init.body));
  assert.deepEqual(Object.keys(saveBody).sort(), ['ciphertext', 'iv', 'salt_id', 'salt_version']);
  assert.equal(saveBody.salt_id, 'journal:v1:server-derived-salt');
  assert.equal(new Headers(calls[2]?.init.headers).get('Authorization'), 'Bearer access-token');
});

test('room helpers create, list, and build encoded websocket stream URLs', async () => {
  assert.equal((await listRooms('access-token'))[0]?.id, 'room-1');
  assert.equal((await createRoom('access-token', 'Study')).title, 'Study');

  const url = roomStreamUrl('room/with space', 'token/with space');
  assert.equal(url, `${WS_BASE_URL}/api/v1/rooms/stream/room%2Fwith%20space?ticket=token%2Fwith+space`);
  assert.deepEqual(
    calls.map((call) => [call.url, call.init.method ?? 'GET']),
    [
      [`${API_BASE_URL}/api/v1/rooms/active`, 'GET'],
      [`${API_BASE_URL}/api/v1/rooms/create`, 'POST'],
    ],
  );
});
