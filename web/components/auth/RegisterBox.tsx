import React, { useState } from 'react';

export default function RegisterBox() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    try {
      const response = await fetch('/api/v1/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();

      if (response.status === 429) {
        // IP rate limited
        setError(data.message);
      } else if (!response.ok) {
        setError(data.message || 'Registration failed');
      } else {
        // Success
        console.log('Registered successfully');
      }
    } catch (err) {
      setError('An unexpected error occurred');
    }
  };

  return (
    <div className="register-box" style={{ maxWidth: '400px', margin: '0 auto', padding: '2rem' }}>
      <h2>Register</h2>
      <form onSubmit={handleRegister}>
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

        {/* Errors / Lockout messages */}
        {error && (
          <div style={{ color: 'red', marginBottom: '1rem' }}>
            {error}
          </div>
        )}

        <button type="submit" style={{ padding: '0.5rem 1rem' }}>Register</button>
      </form>
    </div>
  );
}
