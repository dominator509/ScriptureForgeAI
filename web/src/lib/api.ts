export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8080';
export const WS_BASE_URL = process.env.NEXT_PUBLIC_WS_BASE_URL ?? 'ws://localhost:8080';

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
