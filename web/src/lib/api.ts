type WebRuntimeEnv = {
  [key: string]: string | undefined;
  NEXT_PUBLIC_API_BASE_URL?: string;
  NEXT_PUBLIC_WS_BASE_URL?: string;
  NEXT_PUBLIC_API_REQUEST_TIMEOUT_MS?: string;
  NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT?: string;
};

export interface WebRuntimeConfig {
  apiBaseUrl: string;
  wsBaseUrl: string;
  requestTimeoutMs: number;
  strictStaging: boolean;
}

const localAPIBaseURL = 'http://localhost:8080';
const localWSBaseURL = 'ws://localhost:8080';
const defaultAPIRequestTimeoutMs = 15000;
const csrfCookieName = 'scriptureforge_csrf';
const csrfHeaderName = 'X-CSRF-Token';

function isStrictWebEnvironment(env: WebRuntimeEnv): boolean {
  const deploymentEnvironment = (env.NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT ?? '').toLowerCase();
  return !['', 'development', 'dev', 'test', 'local'].includes(deploymentEnvironment);
}

function isLocalOrPrivateURL(value: string): boolean {
  try {
    const parsed = new URL(value);
    return isLocalOrPrivateHost(parsed.hostname) || isReservedPlaceholderHost(parsed.hostname);
  } catch {
    return true;
  }
}

function isReservedPlaceholderHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  return host.endsWith('.example')
    || host === 'example.com'
    || host.endsWith('.example.com')
    || host === 'example.org'
    || host.endsWith('.example.org')
    || host === 'example.net'
    || host.endsWith('.example.net')
    || host.endsWith('.test')
    || host.endsWith('.invalid');
}

function isLocalOrPrivateHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host === '::' || host === '::1') {
    return true;
  }
  const mappedIPv4 = ipv4MappedHost(host);
  if (mappedIPv4) {
    return isLocalOrPrivateHost(mappedIPv4);
  }
  if (/^f[cd][0-9a-f]*:/i.test(host) || /^fe[89ab][0-9a-f]*:/i.test(host)) {
    return true;
  }
  const parts = host.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [first, second] = parts;
  return first === 0
    || first === 10
    || first === 127
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

function ipv4MappedHost(host: string): string | null {
  if (!host.startsWith('::ffff:')) {
    return null;
  }
  const mapped = host.slice('::ffff:'.length);
  if (mapped.includes('.')) {
    return mapped;
  }
  const hextets = mapped.split(':').filter(Boolean).map((part) => Number.parseInt(part, 16));
  if (hextets.length === 0 || hextets.length > 2 || hextets.some((part) => !Number.isInteger(part) || part < 0 || part > 0xffff)) {
    return null;
  }
  const value = hextets.length === 1 ? hextets[0] : (hextets[0] << 16) + hextets[1];
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join('.');
}

function assertStrictWebURL(name: string, value: string, protocol: 'https:' | 'wss:'): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute ${protocol}// URL for staging or production web builds`);
  }
  if (parsed.protocol !== protocol || parsed.username !== '' || parsed.password !== '' || parsed.search !== '' || parsed.hash !== '' || isLocalOrPrivateURL(value)) {
    throw new Error(`${name} must use public non-local ${protocol}// for staging or production web builds`);
  }
}

function resolveAPIRequestTimeout(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === '') return defaultAPIRequestTimeoutMs;
  const timeoutMs = Number(raw);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) {
    throw new Error('NEXT_PUBLIC_API_REQUEST_TIMEOUT_MS must be an integer between 1000 and 120000');
  }
  return timeoutMs;
}

function normalizeBaseURL(value: string): string {
  return value.trim().replace(/\/+$/, '');
}

export function resolveWebRuntimeConfig(env: WebRuntimeEnv = process.env): WebRuntimeConfig {
  const strictStaging = isStrictWebEnvironment(env);
  const apiBaseUrl = normalizeBaseURL(env.NEXT_PUBLIC_API_BASE_URL ?? localAPIBaseURL);
  const wsBaseUrl = normalizeBaseURL(env.NEXT_PUBLIC_WS_BASE_URL ?? localWSBaseURL);
  const requestTimeoutMs = resolveAPIRequestTimeout(env.NEXT_PUBLIC_API_REQUEST_TIMEOUT_MS);
  if (strictStaging) {
    assertStrictWebURL('NEXT_PUBLIC_API_BASE_URL', apiBaseUrl, 'https:');
    assertStrictWebURL('NEXT_PUBLIC_WS_BASE_URL', wsBaseUrl, 'wss:');
  }
  return { apiBaseUrl, wsBaseUrl, requestTimeoutMs, strictStaging };
}

const runtimeConfig = resolveWebRuntimeConfig();
export const API_BASE_URL = runtimeConfig.apiBaseUrl;
export const WS_BASE_URL = runtimeConfig.wsBaseUrl;
export const API_REQUEST_TIMEOUT_MS = runtimeConfig.requestTimeoutMs;

export interface AuthSession {
  token: string;
  refresh_token?: string;
  user_id: string;
  organization_id: string;
  role?: string;
  requires_mfa?: boolean;
  mfa_enrollment_token?: string;
  mfa_enrollment_required?: boolean;
}

export interface AuthCredentials {
  email: string;
  password: string;
  organization_id: string;
  mfa_code?: string;
}

export interface RegisterCredentials {
  email: string;
  password: string;
  organization_name: string;
}

export interface MFAEnrollmentResponse {
  secret: string;
}

export interface MFAVerifyResponse {
  verified: boolean;
}

export interface WorkspaceSwitchPayload {
  organization_id: string;
}

export interface WorkspaceSwitchResponse {
  organization_id: string;
}

export interface EncryptedJournalEntry {
  id: string;
  ciphertext: string;
  iv: string;
  salt_id: string;
  salt_version: number;
}

export interface JournalBootstrap {
  salt_id: string;
  salt_version: number;
}

export interface RoomSummary {
  id: string;
  title: string;
  is_active: boolean;
}

export interface RoomEvent {
  type: string;
  room_id: string;
  sequence: number;
  payload: unknown;
  sent_at: string;
}

export interface ApiErrorBody {
  category?: string;
  message?: string;
  code?: number;
  requires_mfa?: boolean;
  user_id?: string;
  organization_id?: string;
  role?: string;
  mfa_enrollment_token?: string;
  mfa_enrollment_required?: boolean;
}

export class ApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody | string | null;
  readonly category?: string;
  readonly requiresMFA: boolean;

  constructor(status: number, body: ApiErrorBody | string | null) {
    const message = typeof body === 'string' ? body : body?.message || `Request failed with ${status}`;
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    this.category = typeof body === 'string' ? undefined : body?.category;
    this.requiresMFA = typeof body !== 'string' && body?.requires_mfa === true;
  }
}

async function fetchWithTimeout(input: RequestInfo | URL, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  let timedOut = false;
  const onAbort = () => controller.abort();
  const timeoutID = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  if (init.signal?.aborted) {
    controller.abort();
  } else {
    init.signal?.addEventListener('abort', onAbort, { once: true });
  }
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    if (timedOut) {
      throw new ApiError(0, { category: 'NETWORK_FAULT', message: `Request timed out after ${timeoutMs}ms` });
    }
    throw error;
  } finally {
    clearTimeout(timeoutID);
    init.signal?.removeEventListener('abort', onAbort);
  }
}

interface SessionBridge {
  getSession: () => AuthSession | null;
  onSessionChange: (session: AuthSession | null) => void;
}

let sessionBridge: SessionBridge | null = null;
let refreshInFlight: Promise<AuthSession | null> | null = null;
let csrfTokenInFlight: Promise<string | null> | null = null;

export function configureSessionBridge(bridge: SessionBridge | null): void {
  sessionBridge = bridge;
  refreshInFlight = null;
  csrfTokenInFlight = null;
}

async function parseErrorBody(response: Response): Promise<ApiErrorBody | string | null> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as ApiErrorBody;
  } catch {
    return text;
  }
}

function readBrowserCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const prefix = `${encodeURIComponent(name)}=`;
  for (const part of document.cookie.split(';')) {
    const value = part.trim();
    if (!value.startsWith(prefix)) continue;
    return decodeURIComponent(value.slice(prefix.length));
  }
  return null;
}

function isUnsafeMethod(method: string): boolean {
  return method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
}

async function ensureBrowserCSRFToken(requestTimeoutMs: number): Promise<string | null> {
  if (typeof document === 'undefined') {
    return null;
  }
  const cookieToken = readBrowserCookie(csrfCookieName);
  if (cookieToken) return cookieToken;
  if (!csrfTokenInFlight) {
    csrfTokenInFlight = fetchWithTimeout(`${API_BASE_URL}/api/v1/auth/csrf`, {
      method: 'GET',
      credentials: 'include',
      headers: { 'X-ScriptureForge-Client': 'web' },
    }, requestTimeoutMs).then(async (response) => {
      if (!response.ok) throw new ApiError(response.status, await parseErrorBody(response));
      const body = await response.json() as { csrf_token?: string };
      if (!body.csrf_token) {
        throw new ApiError(0, { category: 'SECURITY_FAULT', message: 'Browser CSRF token was not issued' });
      }
      return body.csrf_token;
    }).finally(() => {
      csrfTokenInFlight = null;
    });
  }
  return csrfTokenInFlight;
}

function canRefreshForPath(path: string): boolean {
  return !path.includes('/auth/');
}

async function rotateSession(expiredToken: string, requestTimeoutMs: number): Promise<AuthSession | null> {
  const bridge = sessionBridge;
  if (!bridge) return null;
  const current = bridge.getSession();
  if (!current?.organization_id) return null;
  if (current.token !== expiredToken) return current;
  if (!refreshInFlight) {
    refreshInFlight = refreshSession(current.refresh_token ?? null, current.organization_id, requestTimeoutMs)
      .then((session) => {
        bridge.onSessionChange(session);
        return session;
      })
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.status === 401) {
          bridge.onSessionChange(null);
        }
        return null;
      })
      .finally(() => {
        refreshInFlight = null;
      });
  }
  return refreshInFlight;
}

export async function apiRequest<T>(
  path: string,
  token: string | null,
  init: RequestInit = {},
  allowRefresh = true,
  requestTimeoutMs = API_REQUEST_TIMEOUT_MS,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  headers.set('X-ScriptureForge-Client', 'web');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const method = (init.method ?? 'GET').toUpperCase();
  if (isUnsafeMethod(method)) {
    const csrfToken = await ensureBrowserCSRFToken(requestTimeoutMs);
    if (csrfToken) headers.set(csrfHeaderName, csrfToken);
  }

  const response = await fetchWithTimeout(`${API_BASE_URL}${path}`, { ...init, credentials: 'include', headers }, requestTimeoutMs);
  if (response.status === 401 && token && allowRefresh && canRefreshForPath(path)) {
    const session = await rotateSession(token, requestTimeoutMs);
    if (session?.token && session.token !== token) {
      return apiRequest<T>(path, session.token, init, false, requestTimeoutMs);
    }
  }
  if (!response.ok) {
    throw new ApiError(response.status, await parseErrorBody(response));
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export function register(credentials: RegisterCredentials): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/register', null, {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
}

export function login(credentials: AuthCredentials): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/login', null, {
    method: 'POST',
    body: JSON.stringify(credentials),
  }).catch((error: unknown) => {
    if (error instanceof ApiError && error.requiresMFA && typeof error.body !== 'string' && error.body) {
      return {
        token: '',
        refresh_token: '',
        user_id: error.body.user_id ?? '',
        organization_id: error.body.organization_id ?? credentials.organization_id,
        role: error.body.role,
        requires_mfa: true,
        mfa_enrollment_token: error.body.mfa_enrollment_token,
        mfa_enrollment_required: error.body.mfa_enrollment_required,
      };
    }
    throw error;
  });
}

export function enrollMFA(token: string): Promise<MFAEnrollmentResponse> {
  return apiRequest<MFAEnrollmentResponse>('/api/v1/auth/mfa/enroll', token, {
    method: 'POST',
    body: '{}',
  });
}

export function verifyMFA(token: string, mfaCode: string): Promise<MFAVerifyResponse> {
  return apiRequest<MFAVerifyResponse>('/api/v1/auth/mfa/verify', token, {
    method: 'POST',
    body: JSON.stringify({ mfa_code: mfaCode }),
  });
}

export function refreshSession(
  refreshToken: string | null,
  organizationId: string,
  requestTimeoutMs = API_REQUEST_TIMEOUT_MS,
): Promise<AuthSession> {
  const body = { organization_id: organizationId, ...(refreshToken ? { refresh_token: refreshToken } : {}) };
  return apiRequest<AuthSession>('/api/v1/auth/refresh', null, {
    method: 'POST',
    body: JSON.stringify(body),
  }, true, requestTimeoutMs);
}

export function logout(
  token: string,
  refreshToken: string | null,
  organizationId: string,
): Promise<void> {
  const body = { organization_id: organizationId, ...(refreshToken ? { refresh_token: refreshToken } : {}) };
  return apiRequest<void>('/api/v1/auth/logout', token, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export function switchWorkspace(token: string, organizationID: string): Promise<WorkspaceSwitchResponse> {
  return apiRequest<WorkspaceSwitchResponse>('/api/v1/workspaces/switch', token, {
    method: 'POST',
    body: JSON.stringify({ organization_id: organizationID } as WorkspaceSwitchPayload),
  });
}

export function listJournalEntries(token: string): Promise<EncryptedJournalEntry[]> {
  return apiRequest<EncryptedJournalEntry[]>('/api/v1/journal_entries', token);
}

export function getJournalBootstrap(token: string): Promise<JournalBootstrap> {
  return apiRequest<JournalBootstrap>('/api/v1/journal/bootstrap', token);
}

export function saveJournalEntry(
  token: string,
  payload: Omit<EncryptedJournalEntry, 'id'>,
): Promise<EncryptedJournalEntry> {
  return apiRequest<EncryptedJournalEntry>('/api/v1/journal_entries', token, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export function getJournalEntry(token: string, entryID: string): Promise<EncryptedJournalEntry> {
  return apiRequest<EncryptedJournalEntry>(`/api/v1/journal_entries/${encodeURIComponent(entryID)}`, token);
}

export function getRoomState(token: string, roomID: string): Promise<RoomEvent> {
  return apiRequest<RoomEvent>(`/api/v1/rooms/state/${encodeURIComponent(roomID)}`, token);
}

export function listRooms(token: string): Promise<RoomSummary[]> {
  return apiRequest<RoomSummary[]>('/api/v1/rooms/active', token);
}

export function createRoom(token: string, title: string): Promise<RoomSummary> {
  return apiRequest<RoomSummary>('/api/v1/rooms/create', token, {
    method: 'POST',
    body: JSON.stringify({ title }),
  });
}

export const ROOM_STREAM_SUBPROTOCOL = 'scriptureforge-bearer';

export function roomStreamUrl(roomID: string): string {
  return `${WS_BASE_URL}/api/v1/rooms/stream/${encodeURIComponent(roomID)}`;
}

export function roomStreamProtocols(token: string): [string, string] {
  return [ROOM_STREAM_SUBPROTOCOL, token];
}
