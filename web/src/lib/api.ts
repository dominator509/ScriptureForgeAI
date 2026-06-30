type WebRuntimeEnv = {
  [key: string]: string | undefined;
  NEXT_PUBLIC_API_BASE_URL?: string;
  NEXT_PUBLIC_WS_BASE_URL?: string;
  NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT?: string;
};

export interface WebRuntimeConfig {
  apiBaseUrl: string;
  wsBaseUrl: string;
  strictStaging: boolean;
}

const localAPIBaseURL = 'http://localhost:8080';
const localWSBaseURL = 'ws://localhost:8080';

function isStrictWebEnvironment(env: WebRuntimeEnv): boolean {
  const deploymentEnvironment = (env.NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT ?? '').toLowerCase();
  return ['staging', 'production', 'prod'].includes(deploymentEnvironment);
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
  if (parsed.protocol !== protocol || isLocalOrPrivateURL(value)) {
    throw new Error(`${name} must use public non-local ${protocol}// for staging or production web builds`);
  }
}

export function resolveWebRuntimeConfig(env: WebRuntimeEnv = process.env): WebRuntimeConfig {
  const strictStaging = isStrictWebEnvironment(env);
  const apiBaseUrl = env.NEXT_PUBLIC_API_BASE_URL ?? localAPIBaseURL;
  const wsBaseUrl = env.NEXT_PUBLIC_WS_BASE_URL ?? localWSBaseURL;
  if (strictStaging) {
    assertStrictWebURL('NEXT_PUBLIC_API_BASE_URL', apiBaseUrl, 'https:');
    assertStrictWebURL('NEXT_PUBLIC_WS_BASE_URL', wsBaseUrl, 'wss:');
  }
  return { apiBaseUrl, wsBaseUrl, strictStaging };
}

const runtimeConfig = resolveWebRuntimeConfig();
export const API_BASE_URL = runtimeConfig.apiBaseUrl;
export const WS_BASE_URL = runtimeConfig.wsBaseUrl;

export interface AuthSession {
  token: string;
  refresh_token: string;
  user_id: string;
  organization_id: string;
}

export interface AuthCredentials {
  email: string;
  password: string;
  organization_id: string;
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

export async function apiRequest<T>(
  path: string,
  token: string | null,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `Request failed with ${response.status}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export function register(credentials: AuthCredentials): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/register', null, {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
}

export function login(credentials: AuthCredentials): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/login', null, {
    method: 'POST',
    body: JSON.stringify(credentials),
  });
}

export function refreshSession(
  refreshToken: string,
  organizationId: string,
): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/refresh', null, {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken, organization_id: organizationId }),
  });
}

export function logout(
  token: string,
  refreshToken: string,
  organizationId: string,
): Promise<void> {
  return apiRequest<void>('/api/v1/auth/logout', token, {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken, organization_id: organizationId }),
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

export function listRooms(token: string): Promise<RoomSummary[]> {
  return apiRequest<RoomSummary[]>('/api/v1/rooms/active', token);
}

export function createRoom(token: string, title: string): Promise<RoomSummary> {
  return apiRequest<RoomSummary>('/api/v1/rooms/create', token, {
    method: 'POST',
    body: JSON.stringify({ title }),
  });
}

export function roomStreamUrl(roomID: string, token: string): string {
  const params = new URLSearchParams({ ticket: token });
  return `${WS_BASE_URL}/api/v1/rooms/stream/${encodeURIComponent(roomID)}?${params.toString()}`;
}
