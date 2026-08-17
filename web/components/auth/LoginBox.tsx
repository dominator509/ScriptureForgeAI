import React, { useState } from 'react';

export default function LoginBox() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [warning, setWarning] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setWarning('');

    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.status === 429) {
        // IP rate limited
        setError(data.message);
      } else if (response.status === 403 || data.status === 'locked') {
        // Account locked - redirect to password recovery would happen here
        setError(data.message);
        // Example: router.push('/password-recovery')
      } else if (!response.ok) {
        setError(data.message || 'Login failed');
        if (data.warning) {
          setWarning(data.warning);
        }
      } else {
        // Success
        console.log('Logged in successfully', data.token);
      }
    } catch (err) {
      setError('An unexpected error occurred');
    }
  };

  return (
    <div className="login-box" style={{ maxWidth: '400px', margin: '0 auto', padding: '2rem' }}>
      <h2>Login</h2>
      <form onSubmit={handleLogin}>
        <div>
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            required
            style={{ width: '100%', marginBottom: '1rem' }}
          />
        </div>
        <div>
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
            style={{ width: '100%', marginBottom: '1rem' }}
          />
        </div>

        {/* Warning delivered in red text as requested */}
        {warning && (
          <div style={{ color: 'red', fontWeight: 'bold', marginBottom: '1rem' }}>
            Warning: {warning}
          </div>
        )}

        {/* Errors / Lockout messages */}
        {error && (
          <div style={{ color: 'red', marginBottom: '1rem' }}>
            {error}
          </div>
        )}

        <button type="submit" style={{ padding: '0.5rem 1rem' }}>Login</button>
      </form>
    </div>
  );
}
