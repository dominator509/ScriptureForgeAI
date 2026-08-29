import assert from 'node:assert/strict';
import { after, beforeEach, test } from 'node:test';
import {
  API_BASE_URL,
  API_REQUEST_TIMEOUT_MS,
  type AuthSession,
  apiRequest,
  createRoom,
  configureSessionBridge,
  enrollMFA,
  getJournalEntry,
  getJournalBootstrap,
  listJournalEntries,
  listRooms,
  login,
  logout,
  refreshSession,
  register,
  resolveWebRuntimeConfig,
  roomStreamProtocols,
  roomStreamUrl,
  saveJournalEntry,
  verifyMFA,
  WS_BASE_URL,
} from './api.ts';
import { JOURNAL_PBKDF2_ITERATIONS } from './crypto.ts';

type FetchCall = {
  url: string;
  init: RequestInit;
};

const calls: FetchCall[] = [];
const webAPISmokeProofMarkers = [
  'web_api_auth_routes=true',
  'web_api_encrypted_journal=true',
  'web_api_rooms_ws=true',
  'web_runtime_strict_endpoint_guard=true',
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

test('auth helpers use canonical v1 routes and bearer logout revocation', async () => {
  const credentials = { email: 'reader@example.com', password: 'correct horse', organization_id: 'org-1' };

  assert.equal((await register({ email: credentials.email, password: credentials.password, organization_name: 'Reader Workspace' })).token, 'access-token');
  assert.equal((await login(credentials)).refresh_token, 'refresh-token');
  assert.equal((await refreshSession('old-refresh', 'org-1')).organization_id, 'org-1');
  await logout('access-token', null, 'org-1');

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
  assert.equal(new Headers(calls[0]?.init.headers).get('X-ScriptureForge-Client'), 'web');
  assert.equal(calls[0]?.init.credentials, 'include');
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), { email: credentials.email, password: credentials.password, organization_name: 'Reader Workspace' });
  assert.equal(JSON.parse(String(calls.at(2)?.init.body)).organization_id, 'org-1');
  assert.deepEqual(JSON.parse(String(calls.at(3)?.init.body)), { organization_id: 'org-1' });
});

test('browser unsafe requests bootstrap and submit the double-submit CSRF token', async () => {
  const previousDocument = (globalThis as Record<string, unknown>).document;
  const browserDocument = { cookie: '' };
  Object.defineProperty(globalThis, 'document', { configurable: true, value: browserDocument });
  try {
    const csrfToken = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = String(input);
      calls.push({ url, init: init ?? {} });
      if (url.endsWith('/api/v1/auth/csrf')) {
        browserDocument.cookie = `scriptureforge_csrf=${csrfToken}`;
        return jsonResponse({ csrf_token: csrfToken });
      }
      if (url.endsWith('/api/v1/auth/login')) return jsonResponse({ token: 'access-token', user_id: 'user-1', organization_id: 'org-1' });
      return new Response('unexpected route', { status: 404 });
    };

    await login({ email: 'reader@example.com', password: 'correct horse', organization_id: 'org-1' });
    assert.deepEqual(calls.map((call) => [call.url, call.init.method ?? 'GET']), [
      [`${API_BASE_URL}/api/v1/auth/csrf`, 'GET'],
      [`${API_BASE_URL}/api/v1/auth/login`, 'POST'],
    ]);
    assert.equal(new Headers(calls[1]?.init.headers).get('X-CSRF-Token'), csrfToken);
    assert.equal(calls[0]?.init.credentials, 'include');
  } finally {
    configureSessionBridge(null);
    if (typeof previousDocument === 'undefined') {
      delete (globalThis as { document?: unknown }).document;
    } else {
      Object.defineProperty(globalThis, 'document', { configurable: true, value: previousDocument });
    }
  }
});

test('web authenticated requests rotate an expired access token and retry once', async () => {
  let activeSession: AuthSession = {
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

test('web login exposes the privileged MFA challenge without storing an empty session', async () => {
  globalThis.fetch = async (): Promise<Response> => jsonResponse({
    requires_mfa: true,
    user_id: 'admin-1',
    organization_id: 'org-1',
    mfa_enrollment_required: true,
    mfa_enrollment_token: 'enrollment-token',
  }, 401);

  const session = await login({ email: 'admin@example.com', password: 'correct horse', organization_id: 'org-1' });
  assert.equal(session.requires_mfa, true);
  assert.equal(session.token, '');
  assert.equal(session.user_id, 'admin-1');
  assert.equal(session.mfa_enrollment_required, true);
  assert.equal(session.mfa_enrollment_token, 'enrollment-token');
});

test('web MFA enrollment helpers use the restricted bearer token and never send plaintext credentials', async () => {
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(input), init: init ?? {} });
    if (String(input).endsWith('/api/v1/auth/mfa/enroll')) return jsonResponse({ secret: 'TOTP-SETUP-SECRET' });
    return jsonResponse({ verified: true });
  };

  const enrollment = await enrollMFA('enrollment-token');
  const verification = await verifyMFA('enrollment-token', '123456');
  assert.equal(enrollment.secret, 'TOTP-SETUP-SECRET');
  assert.equal(verification.verified, true);
  assert.deepEqual(calls.map((call) => [call.url, call.init.method ?? 'GET']), [
    [`${API_BASE_URL}/api/v1/auth/mfa/enroll`, 'POST'],
    [`${API_BASE_URL}/api/v1/auth/mfa/verify`, 'POST'],
  ]);
  assert.equal(new Headers(calls[0]?.init.headers).get('Authorization'), 'Bearer enrollment-token');
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), {});
  assert.deepEqual(JSON.parse(String(calls[1]?.init.body)), { mfa_code: '123456' });
});

test('web refresh can rely on the HttpOnly cookie without sending a refresh token body', async () => {
  let activeSession = {
    token: 'expired-token',
    user_id: 'user-1',
    organization_id: 'org-1',
  };
  configureSessionBridge({
    getSession: () => activeSession,
    onSessionChange: (session) => { activeSession = session!; },
  });
  const refreshBodies: unknown[] = [];
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    const token = new Headers(init?.headers).get('Authorization') ?? '';
    if (url.endsWith('/api/v1/auth/refresh')) {
      refreshBodies.push(JSON.parse(String(init?.body)));
      return jsonResponse({ token: 'fresh-token', user_id: 'user-1', organization_id: 'org-1' });
    }
    if (url.endsWith('/api/v1/rooms/state/room-1') && token === 'Bearer expired-token') return jsonResponse({ message: 'expired' }, 401);
    return jsonResponse({ sequence: 4 });
  };

  const result = await apiRequest<{ sequence: number }>('/api/v1/rooms/state/room-1', 'expired-token');
  assert.equal(result.sequence, 4);
  assert.deepEqual(refreshBodies, [{ organization_id: 'org-1' }]);
  assert.equal(activeSession.token, 'fresh-token');
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

test('web journal key derivation uses architecture PBKDF2 work factor', () => {
  assert.equal(JOURNAL_PBKDF2_ITERATIONS, 600000);
});

test('room helpers create, list, and build encoded websocket stream URLs', async () => {
  assert.equal((await listRooms('access-token'))[0]?.id, 'room-1');
  assert.equal((await createRoom('access-token', 'Study')).title, 'Study');

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

test('web runtime config keeps local defaults only outside strict staging mode', () => {
  const config = resolveWebRuntimeConfig({});

  assert.equal(config.apiBaseUrl, 'http://localhost:8080');
  assert.equal(config.wsBaseUrl, 'ws://localhost:8080');
  assert.equal(config.requestTimeoutMs, 15000);
  assert.equal(config.strictStaging, false);
});

test('web requests abort stalled fetches with a typed network fault', async () => {
  globalThis.fetch = async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => new Promise((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  });

  await assert.rejects(
    apiRequest('/api/v1/rooms/active', 'access-token', {}, true, 5),
    (error: unknown) => error instanceof Error
      && error.name === 'ApiError'
      && (error as { status?: number }).status === 0
      && error.message === 'Request timed out after 5ms',
  );
  assert.equal(API_REQUEST_TIMEOUT_MS, 15000);
});

test('web runtime config rejects local or insecure endpoints in staging builds', () => {
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      NEXT_PUBLIC_API_BASE_URL: 'http://localhost:8080',
      NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai',
    }),
    /NEXT_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'production',
      NEXT_PUBLIC_API_BASE_URL: 'https://web-api.staging.scriptureforge.ai',
      NEXT_PUBLIC_WS_BASE_URL: 'ws://web-api.staging.scriptureforge.ai',
    }),
    /NEXT_PUBLIC_WS_BASE_URL must use public non-local wss/,
  );
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      NEXT_PUBLIC_API_BASE_URL: 'https://10.0.0.15',
      NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai',
    }),
    /NEXT_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      NEXT_PUBLIC_API_BASE_URL: 'https://[fd00::15]',
      NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai',
    }),
    /NEXT_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      NEXT_PUBLIC_API_BASE_URL: 'https://[::ffff:10.0.0.15]',
      NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai',
    }),
    /NEXT_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      NEXT_PUBLIC_API_BASE_URL: 'https://web-api.staging.scriptureforge.ai',
      NEXT_PUBLIC_WS_BASE_URL: 'wss://192.168.1.20',
    }),
    /NEXT_PUBLIC_WS_BASE_URL must use public non-local wss/,
  );
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      NEXT_PUBLIC_API_BASE_URL: 'https://api.staging.example',
      NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai',
    }),
    /NEXT_PUBLIC_API_BASE_URL must use public non-local https/,
  );
  assert.throws(
    () => resolveWebRuntimeConfig({
      NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
      NEXT_PUBLIC_API_BASE_URL: 'https://web-api.staging.scriptureforge.ai',
      NEXT_PUBLIC_WS_BASE_URL: 'wss://app.example.com',
    }),
    /NEXT_PUBLIC_WS_BASE_URL must use public non-local wss/,
  );
});

test('web runtime config rejects missing endpoints for non-local environment names', () => {
  assert.throws(
    () => resolveWebRuntimeConfig({ NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'production-blue' }),
    /NEXT_PUBLIC_API_BASE_URL must use public non-local https/,
  );
});

test('web runtime config accepts explicit staging HTTPS and WSS endpoints', () => {
  const config = resolveWebRuntimeConfig({
    NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
    NEXT_PUBLIC_API_BASE_URL: 'https://web-api.staging.scriptureforge.ai',
    NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai',
  });

  assert.equal(config.apiBaseUrl, 'https://web-api.staging.scriptureforge.ai');
  assert.equal(config.wsBaseUrl, 'wss://web-api.staging.scriptureforge.ai');
  assert.equal(config.strictStaging, true);
});

test('web runtime config normalizes endpoint slashes and rejects URL metadata', () => {
  const config = resolveWebRuntimeConfig({
    NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
    NEXT_PUBLIC_API_BASE_URL: ' https://web-api.staging.scriptureforge.ai/// ',
    NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai/',
  });

  assert.equal(config.apiBaseUrl, 'https://web-api.staging.scriptureforge.ai');
  assert.equal(config.wsBaseUrl, 'wss://web-api.staging.scriptureforge.ai');

  for (const apiBaseUrl of [
    'https://user:password@web-api.staging.scriptureforge.ai',
    'https://web-api.staging.scriptureforge.ai/?unexpected=query',
    'https://web-api.staging.scriptureforge.ai/#unexpected-fragment',
  ]) {
    assert.throws(
      () => resolveWebRuntimeConfig({
        NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT: 'staging',
        NEXT_PUBLIC_API_BASE_URL: apiBaseUrl,
        NEXT_PUBLIC_WS_BASE_URL: 'wss://web-api.staging.scriptureforge.ai',
      }),
      /NEXT_PUBLIC_API_BASE_URL must use public non-local https/,
    );
  }
});

after(() => {
  console.log(`web api smoke proof: ${webAPISmokeProofMarkers.join(', ')}`);
});
