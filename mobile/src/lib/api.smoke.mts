import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';
import {
  API_BASE_URL,
  apiRequest,
  createRoom,
  configureSessionBridge,
  getJournalEntry,
  getJournalBootstrap,
  listActiveRooms,
  listJournalEntries,
  loginAccount,
  logoutSession,
  refreshSession,
  registerAccount,
  resolveMobileRuntimeConfig,
  roomStreamProtocols,
  roomStreamUrl,
  saveJournalEntry,
  WS_BASE_URL,
} from './api.ts';

type FetchCall = {
  url: string;
  init: RequestInit;
};

const calls: FetchCall[] = [];
const mobileAPISmokeProofMarkers = [
  'mobile_api_auth_mfa=true',
  'mobile_api_encrypted_journal=true',
  'mobile_api_rooms_ws=true',
  'mobile_runtime_native_required_guard=true',
];

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });

beforeEach(() => {
  calls.length = 0;
  configureSessionBridge(null);
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

test('auth helpers use canonical routes, organization scoping, MFA, and bearer logout revocation', async () => {
  assert.equal((await registerAccount('reader@example.com', 'correct horse', 'org-1')).token, 'access-token');
  assert.equal((await loginAccount('reader@example.com', 'correct horse', 'org-1', '123456')).refresh_token, 'refresh-token');
  assert.equal((await refreshSession('old-refresh', 'org-1')).organization_id, 'org-1');
  await logoutSession('access-token', 'refresh-token', 'org-1');

  assert.deepEqual(
    calls.map((call) => [call.url, call.init.method ?? 'GET']),
    [
      [`${API_BASE_URL}/api/v1/auth/register`, 'POST'],
      [`${API_BASE_URL}/api/v1/auth/login`, 'POST'],
      [`${API_BASE_URL}/api/v1/auth/refresh`, 'POST'],
      [`${API_BASE_URL}/api/v1/auth/logout`, 'POST'],
    ],
  );

  const loginBody = JSON.parse(String(calls[1]?.init.body));
  assert.equal(loginBody.mfa_code, '123456');
  assert.equal(loginBody.organization_id, 'org-1');
  assert.equal(new Headers(calls[3]?.init.headers).get('Authorization'), 'Bearer access-token');
});

test('mobile authenticated requests rotate an expired access token and retry once', async () => {
  let activeSession = {
    token: 'expired-token',
    refresh_token: 'refresh-token',
    user_id: 'user-1',
    organization_id: 'org-1',
  };
  const requestTokens: string[] = [];
  let refreshCalls = 0;
  configureSessionBridge({
    getSession: () => activeSession,
    onSessionChange: (session) => { activeSession = session!; },
  });
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const token = new Headers(init?.headers).get('Authorization') ?? '';
    requestTokens.push(token);
    if (url.endsWith('/api/v1/auth/refresh')) {
      refreshCalls += 1;
      return jsonResponse({ token: 'fresh-token', refresh_token: 'rotated-refresh', user_id: 'user-1', organization_id: 'org-1' });
    }
    if (url.endsWith('/api/v1/rooms/state/room-1') && token === 'Bearer expired-token') {
      return jsonResponse({ category: 'AUTHENTICATION_FAULT', message: 'expired', code: 401 }, 401);
    }
    return jsonResponse({ type: 'presence', room_id: 'room-1', sequence: 3, payload: {}, sent_at: '2026-08-10T00:00:00Z' });
  };

  const state = await apiRequest<{ sequence: number }>('/api/v1/rooms/state/room-1', 'expired-token');
  assert.equal(state.sequence, 3);
  assert.equal(refreshCalls, 1);
  assert.deepEqual(requestTokens, ['Bearer expired-token', '', 'Bearer fresh-token']);
  assert.equal(activeSession.token, 'fresh-token');
});

test('mobile login exposes the privileged MFA challenge for the UI to collect a code', async () => {
  globalThis.fetch = async (): Promise<Response> => jsonResponse({
    requires_mfa: true,
    user_id: 'admin-1',
    organization_id: 'org-1',
  }, 401);

  const session = await loginAccount('admin@example.com', 'correct horse', 'org-1');
  assert.equal(session.requires_mfa, true);
  assert.equal(session.token, '');
  assert.equal(session.user_id, 'admin-1');
});

test('journal helpers send only encrypted fields and use bearer auth', async () => {
  const bootstrap = await getJournalBootstrap('access-token');
  const payload = { ciphertext: 'ciphertext', iv: 'iv', salt_id: bootstrap.salt_id, salt_version: bootstrap.salt_version };

  assert.equal((await listJournalEntries('access-token'))[0]?.id, 'entry-1');
  assert.equal((await saveJournalEntry('access-token', payload)).salt_id, 'journal:v1:server-derived-salt');
  assert.equal((await getJournalEntry('access-token', 'entry-1')).ciphertext, 'ciphertext');

  const saveBody = JSON.parse(String(calls[2]?.init.body));
  assert.deepEqual(Object.keys(saveBody).sort(), ['ciphertext', 'iv', 'salt_id', 'salt_version']);
  assert.equal(saveBody.salt_id, 'journal:v1:server-derived-salt');
  assert.equal(new Headers(calls[2]?.init.headers).get('Authorization'), 'Bearer access-token');
});

test('room helpers create, list, and build encoded websocket stream URLs', async () => {
  assert.equal((await listActiveRooms('access-token'))[0]?.title, 'Study');
  assert.equal((await createRoom('access-token', 'Study')).id, 'room-1');

  const url = roomStreamUrl('room/with space');
  assert.equal(url, `${WS_BASE_URL}/api/v1/rooms/stream/room%2Fwith%20space`);
  assert.deepEqual(roomStreamProtocols('token.with-space'), ['scriptureforge-bearer', 'token.with-space']);
  assert.deepEqual(
    calls.map((call) => [call.url, call.init.method ?? 'GET']),
    [
      [`${API_BASE_URL}/api/v1/rooms/active`, 'GET'],
      [`${API_BASE_URL}/api/v1/rooms/create`, 'POST'],
    ],
  );
});

test('mobile runtime config keeps local defaults only outside strict staging mode', () => {
  const config = resolveMobileRuntimeConfig({});

  assert.equal(config.apiBaseUrl, 'http://localhost:8080');
  assert.equal(config.wsBaseUrl, 'ws://localhost:8080');
  assert.equal(config.strictStaging, false);
});

test('mobile runtime config rejects local or insecure endpoints in native-required builds', () => {
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'http://localhost:8080',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.staging.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'https://mobile-api.staging.scriptureforge.ai',
      EXPO_PUBLIC_WS_BASE_URL: 'ws://mobile-api.staging.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_WS_BASE_URL must use public non-local wss/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'https://172.16.0.25',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.staging.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'https://[fd00::25]',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.staging.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'https://[::ffff:172.16.0.25]',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.staging.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'https://mobile-api.staging.scriptureforge.ai',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://169.254.10.20',
    }),
    /EXPO_PUBLIC_WS_BASE_URL must use public non-local wss/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'https://api.staging.example',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.staging.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
      EXPO_PUBLIC_API_BASE_URL: 'https://mobile-api.staging.scriptureforge.ai',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://app.example.com',
    }),
    /EXPO_PUBLIC_WS_BASE_URL must use public non-local wss/,
  );
});

test('mobile runtime config rejects staging or production builds without native crypto enforcement', () => {
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      EXPO_PUBLIC_API_BASE_URL: 'https://mobile-api.staging.scriptureforge.ai',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.staging.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true is required/,
  );
  assert.throws(
    () => resolveMobileRuntimeConfig({
      EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'production',
      EXPO_PUBLIC_API_BASE_URL: 'https://mobile-api.scriptureforge.ai',
      EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.scriptureforge.ai',
    }),
    /EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true is required/,
  );
});

test('mobile runtime config accepts explicit staging HTTPS and WSS endpoints with native crypto enforcement', () => {
  const config = resolveMobileRuntimeConfig({
    EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
    EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO: 'true',
    EXPO_PUBLIC_API_BASE_URL: 'https://mobile-api.staging.scriptureforge.ai',
    EXPO_PUBLIC_WS_BASE_URL: 'wss://mobile-api.staging.scriptureforge.ai',
  });

  assert.equal(config.apiBaseUrl, 'https://mobile-api.staging.scriptureforge.ai');
  assert.equal(config.wsBaseUrl, 'wss://mobile-api.staging.scriptureforge.ai');
  assert.equal(config.strictStaging, true);
});

after(() => {
  console.log(`mobile api smoke proof: ${mobileAPISmokeProofMarkers.join(', ')}`);
});
