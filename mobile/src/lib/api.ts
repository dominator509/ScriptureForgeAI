type MobileRuntimeEnv = {
  [key: string]: string | undefined;
  EXPO_PUBLIC_API_BASE_URL?: string;
  EXPO_PUBLIC_WS_BASE_URL?: string;
  EXPO_PUBLIC_API_REQUEST_TIMEOUT_MS?: string;
  EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT?: string;
  EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO?: string;
};

export interface MobileRuntimeConfig {
  apiBaseUrl: string;
  wsBaseUrl: string;
  requestTimeoutMs: number;
  strictStaging: boolean;
}

const localAPIBaseURL = 'http://localhost:8080';
const localWSBaseURL = 'ws://localhost:8080';
const defaultAPIRequestTimeoutMs = 15000;

function isStrictMobileEnvironment(env: MobileRuntimeEnv): boolean {
  const deploymentEnvironment = (env.EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT ?? '').toLowerCase();
  return env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO === 'true' || ['staging', 'production', 'prod'].includes(deploymentEnvironment);
}

function assertNativeCryptoRequired(env: MobileRuntimeEnv): void {
  const deploymentEnvironment = (env.EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT ?? '').toLowerCase();
  if (['staging', 'production', 'prod'].includes(deploymentEnvironment) && env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO !== 'true') {
    throw new Error('EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true is required for staging or production mobile builds');
  }
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

function assertStrictMobileURL(name: string, value: string, protocol: 'https:' | 'wss:'): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute ${protocol}// URL for staging or production mobile builds`);
  }
  if (parsed.protocol !== protocol || isLocalOrPrivateURL(value)) {
    throw new Error(`${name} must use public non-local ${protocol}// for staging or production mobile builds`);
  }
}

function resolveAPIRequestTimeout(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === '') return defaultAPIRequestTimeoutMs;
  const timeoutMs = Number(raw);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) {
    throw new Error('EXPO_PUBLIC_API_REQUEST_TIMEOUT_MS must be an integer between 1000 and 120000');
  }
  return timeoutMs;
}

export function resolveMobileRuntimeConfig(env: MobileRuntimeEnv = process.env): MobileRuntimeConfig {
  const strictStaging = isStrictMobileEnvironment(env);
  const apiBaseUrl = env.EXPO_PUBLIC_API_BASE_URL ?? localAPIBaseURL;
  const wsBaseUrl = env.EXPO_PUBLIC_WS_BASE_URL ?? localWSBaseURL;
  const requestTimeoutMs = resolveAPIRequestTimeout(env.EXPO_PUBLIC_API_REQUEST_TIMEOUT_MS);
  if (strictStaging) {
    assertNativeCryptoRequired(env);
    assertStrictMobileURL('EXPO_PUBLIC_API_BASE_URL', apiBaseUrl, 'https:');
    assertStrictMobileURL('EXPO_PUBLIC_WS_BASE_URL', wsBaseUrl, 'wss:');
  }
  return { apiBaseUrl, wsBaseUrl, requestTimeoutMs, strictStaging };
}

const runtimeConfig = resolveMobileRuntimeConfig();
export const API_BASE_URL = runtimeConfig.apiBaseUrl;
export const WS_BASE_URL = runtimeConfig.wsBaseUrl;
export const API_REQUEST_TIMEOUT_MS = runtimeConfig.requestTimeoutMs;

export interface AuthSession {
  token: string;
  refresh_token: string;
  user_id: string;
  organization_id: string;
  requires_mfa?: boolean;
  mfa_enrollment_token?: string;
  mfa_enrollment_required?: boolean;
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
  mfa_enrollment_token?: string;
  mfa_enrollment_required?: boolean;
}

export interface MFAEnrollmentResponse {
  secret: string;
}

export interface MFAVerifyResponse {
  verified: boolean;
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

export function configureSessionBridge(bridge: SessionBridge | null): void {
  sessionBridge = bridge;
  refreshInFlight = null;
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

function canRefreshForPath(path: string): boolean {
  return !path.includes('/auth/');
}

async function rotateSession(expiredToken: string, requestTimeoutMs: number): Promise<AuthSession | null> {
  const bridge = sessionBridge;
  if (!bridge) return null;
  const current = bridge.getSession();
  if (!current?.refresh_token || !current.organization_id) return null;
  if (current.token !== expiredToken) return current;
  if (!refreshInFlight) {
    refreshInFlight = refreshSession(current.refresh_token, current.organization_id, requestTimeoutMs)
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

export interface RoomSummary {
  id: string;
  title: string;
  is_active: boolean;
  created_at?: string;
}

export interface EncryptedJournalEntry {
  id: string;
  ciphertext: string;
  iv: string;
  salt_id: string;
  salt_version: number;
}

export interface WorkspaceSwitchPayload {
  organization_id: string;
}

export interface WorkspaceSwitchResponse {
  organization_id: string;
}

export interface JournalBootstrap {
  salt_id: string;
  salt_version: number;
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
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetchWithTimeout(`${API_BASE_URL}${path}`, { ...init, headers }, requestTimeoutMs);
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

export async function registerAccount(email: string, password: string, organizationName: string): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/register', null, {
    method: 'POST',
    body: JSON.stringify({ email, password, organization_name: organizationName }),
  });
}

export async function loginAccount(
  email: string,
  password: string,
  organizationId: string,
  mfaCode?: string,
): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/login', null, {
    method: 'POST',
    body: JSON.stringify({ email, password, organization_id: organizationId, mfa_code: mfaCode }),
  }).catch((error: unknown) => {
    if (error instanceof ApiError && error.requiresMFA && typeof error.body !== 'string' && error.body) {
      return {
        token: '',
        refresh_token: '',
        user_id: error.body.user_id ?? '',
        organization_id: error.body.organization_id ?? organizationId,
        requires_mfa: true,
        mfa_enrollment_token: error.body.mfa_enrollment_token,
        mfa_enrollment_required: error.body.mfa_enrollment_required,
      };
    }
    throw error;
  });
}

export async function enrollMFA(token: string): Promise<MFAEnrollmentResponse> {
  return apiRequest<MFAEnrollmentResponse>('/api/v1/auth/mfa/enroll', token, {
    method: 'POST',
    body: '{}',
  });
}

export async function verifyMFA(token: string, mfaCode: string): Promise<MFAVerifyResponse> {
  return apiRequest<MFAVerifyResponse>('/api/v1/auth/mfa/verify', token, {
    method: 'POST',
    body: JSON.stringify({ mfa_code: mfaCode }),
  });
}

export async function refreshSession(
  refreshToken: string,
  organizationId: string,
  requestTimeoutMs = API_REQUEST_TIMEOUT_MS,
): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/refresh', null, {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken, organization_id: organizationId }),
  }, true, requestTimeoutMs);
}

export async function logoutSession(token: string, refreshToken: string, organizationId: string): Promise<void> {
  await apiRequest<void>('/api/v1/auth/logout', token, {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken, organization_id: organizationId }),
  });
}

export async function switchWorkspace(token: string, organizationId: string): Promise<WorkspaceSwitchResponse> {
  return apiRequest<WorkspaceSwitchResponse>('/api/v1/workspaces/switch', token, {
    method: 'POST',
    body: JSON.stringify({ organization_id: organizationId } as WorkspaceSwitchPayload),
  });
}

export async function listJournalEntries(token: string): Promise<EncryptedJournalEntry[]> {
  return apiRequest<EncryptedJournalEntry[]>('/api/v1/journal_entries', token);
}

export async function getJournalBootstrap(token: string): Promise<JournalBootstrap> {
  return apiRequest<JournalBootstrap>('/api/v1/journal/bootstrap', token);
}

export async function saveJournalEntry(
  token: string,
  payload: Omit<EncryptedJournalEntry, 'id'>,
): Promise<EncryptedJournalEntry> {
  return apiRequest<EncryptedJournalEntry>('/api/v1/journal_entries', token, {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getJournalEntry(token: string, entryID: string): Promise<EncryptedJournalEntry> {
  return apiRequest<EncryptedJournalEntry>(`/api/v1/journal_entries/${encodeURIComponent(entryID)}`, token);
}

export async function getRoomState(token: string, roomID: string): Promise<RoomEvent> {
  return apiRequest<RoomEvent>(`/api/v1/rooms/state/${encodeURIComponent(roomID)}`, token);
}

export async function listActiveRooms(token: string): Promise<RoomSummary[]> {
  return apiRequest<RoomSummary[]>('/api/v1/rooms/active', token);
}

export async function createRoom(token: string, title: string): Promise<RoomSummary> {
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
