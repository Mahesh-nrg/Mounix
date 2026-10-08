import { useState, type FormEvent } from 'react'
import { api, ApiError } from '../api'

interface LoginProps {
  onLoggedIn: () => void
}

export function Login({ onLoggedIn }: LoginProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await api.login(username, password)
      onLoggedIn()
    } catch (err: unknown) {
      setError(
        err instanceof ApiError && err.status === 401 ? 'Incorrect username or password' : 'Login failed',
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>Mobile PT Lab</h1>
        <p className="subtitle">Enter your credentials to continue</p>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Username"
          autoFocus
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
        />
        {error && <div className="error-text">{error}</div>}
        <button type="submit" disabled={submitting || !username || !password}>
          {submitting ? 'Checking...' : 'Log in'}
        </button>
      </form>
    </div>
  )
}
