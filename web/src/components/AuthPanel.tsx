'use client';

import React, { useState } from 'react';
import { login, logout, register } from '../lib/api';
import { useAppStore } from '../lib/store';

export const AuthPanel: React.FC = () => {
  const { token, userId, setSession, clearSession } = useAppStore();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [organizationId, setOrganizationId] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [status, setStatus] = useState('');

  const submit = async (mode: 'login' | 'register') => {
    setStatus('');
    try {
      const session = mode === 'login'
        ? await login({ email, password, organization_id: organizationId, mfa_code: mfaCode || undefined })
        : await register({ email, password, organization_name: organizationName });
      if (session.requires_mfa) {
        clearSession();
        setStatus('MFA code required for this privileged account.');
        return;
      }
      setSession(session);
      setStatus('Signed in');
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Authentication failed');
    }
  };

  const submitLogout = async () => {
    const activeToken = token;
    const activeOrganizationId = useAppStore.getState().organizationId;
    if (!activeToken || !activeOrganizationId) {
      clearSession();
      return;
    }
    try {
      await logout(activeToken, null, activeOrganizationId);
    } catch (err) {
      setStatus(err instanceof Error ? err.message : 'Logout failed');
    } finally {
      clearSession();
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
      <input className="w-full border rounded p-2" placeholder="Organization ID (login)" value={organizationId} onChange={(event) => setOrganizationId(event.target.value)} />
      <input className="w-full border rounded p-2" placeholder="Workspace name (register)" value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} />
      <input className="w-full border rounded p-2" placeholder="MFA code (privileged accounts)" inputMode="numeric" value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} />
      <div className="flex gap-2">
        <button className="px-3 py-2 bg-indigo-600 text-white rounded" onClick={() => void submit('login')}>Login</button>
        <button className="px-3 py-2 bg-gray-900 text-white rounded" onClick={() => void submit('register')}>Register</button>
      </div>
      {status && <div className="text-xs text-blue-700 break-words">{status}</div>}
    </section>
  );
};
