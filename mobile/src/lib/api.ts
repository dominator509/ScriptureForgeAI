export const API_BASE_URL = process.env.EXPO_PUBLIC_API_BASE_URL ?? 'http://localhost:8080';
export const WS_BASE_URL = process.env.EXPO_PUBLIC_WS_BASE_URL ?? 'ws://localhost:8080';

export interface AuthSession {
  token: string;
  refresh_token: string;
  user_id: string;
  organization_id: string;
  requires_mfa?: boolean;
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

export interface JournalBootstrap {
  salt_id: string;
  salt_version: number;
}

export async function apiRequest<T>(path: string, token: string | null, init: RequestInit = {}): Promise<T> {
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

export async function registerAccount(email: string, password: string, organizationId: string): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/register', null, {
    method: 'POST',
    body: JSON.stringify({ email, password, organization_id: organizationId }),
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
  });
}

export async function refreshSession(refreshToken: string, organizationId: string): Promise<AuthSession> {
  return apiRequest<AuthSession>('/api/v1/auth/refresh', null, {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken, organization_id: organizationId }),
  });
}

export async function logoutSession(token: string, refreshToken: string, organizationId: string): Promise<void> {
  await apiRequest<void>('/api/v1/auth/logout', token, {
    method: 'POST',
    body: JSON.stringify({ refresh_token: refreshToken, organization_id: organizationId }),
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

export async function listActiveRooms(token: string): Promise<RoomSummary[]> {
  return apiRequest<RoomSummary[]>('/api/v1/rooms/active', token);
}

export async function createRoom(token: string, title: string): Promise<RoomSummary> {
  return apiRequest<RoomSummary>('/api/v1/rooms/create', token, {
    method: 'POST',
    body: JSON.stringify({ title }),
  });
}

export function roomStreamUrl(roomID: string, token: string): string {
  const params = new URLSearchParams({ ticket: token });
  return `${WS_BASE_URL}/api/v1/rooms/stream/${encodeURIComponent(roomID)}?${params.toString()}`;
}
