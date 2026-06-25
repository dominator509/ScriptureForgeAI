'use client';

import React, { useState } from 'react';
import { login, logout, register } from '../lib/api';
import { useAppStore } from '../lib/store';

export const AuthPanel: React.FC = () => {
  const { token, refreshToken, userId, setSession, clearSession } = useAppStore();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [organizationId, setOrganizationId] = useState('');
  const [status, setStatus] = useState('');

  const submit = async (mode: 'login' | 'register') => {
    setStatus('');
    try {
      const body = { email, password, organization_id: organizationId };
      const session = mode === 'login' ? await login(body) : await register(body);
      setSession(session.token, session.refresh_token, session.user_id, session.organization_id);
      setStatus('Signed in');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Authentication failed');
    }
  };

  const submitLogout = async () => {
    const activeToken = token;
    const activeRefreshToken = refreshToken;
    clearSession();
    if (!activeToken || !activeRefreshToken) return;
    try {
      await logout(activeToken, activeRefreshToken);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Logout failed');
    }
  };

  if (token) {
    return (
      <section className="bg-white border rounded p-4 space-y-3">
        <div className="text-sm text-gray-700">Signed in as {userId}</div>
        <button className="px-3 py-2 bg-gray-900 text-white rounded" onClick={() => void submitLogout()}>Logout</button>
      </section>
    );
  }

  return (
    <section className="bg-white border rounded p-4 space-y-3">
      <input className="w-full border rounded p-2" placeholder="Email" value={email} onChange={(event) => setEmail(event.target.value)} />
      <input className="w-full border rounded p-2" placeholder="Password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
      <input className="w-full border rounded p-2" placeholder="Organization ID" value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} />
      <div className="flex gap-2">
        <button className="px-3 py-2 bg-indigo-600 text-white rounded" onClick={() => void submit('login')}>Login</button>
        <button className="px-3 py-2 bg-gray-900 text-white rounded" onClick={() => void submit('register')}>Register</button>
      </div>
      {status && <div className="text-xs text-blue-700 break-words">{status}</div>}
    </section>
  );
};
