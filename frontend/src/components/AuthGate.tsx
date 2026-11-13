import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { ApiError, getCurrentUser, setAuthUser, signIn, signOut, type AuthUser } from '../services/api'
import Logo from './Logo'


export default function AuthGate({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [sessionAttempt, setSessionAttempt] = useState(0)
  const [sessionUnavailable, setSessionUnavailable] = useState(false)

  useEffect(() => {
    let active = true
    const expired = () => { setAuthUser(null); setUser(null) }
    window.addEventListener('talged:session-expired', expired)
    getCurrentUser()
      .then((value) => {
        if (active) { setAuthUser(value); setUser(value) }
      })
      .catch((reason: unknown) => {
        if (active && (!(reason instanceof ApiError) || reason.status !== 401)) {
          setSessionUnavailable(true)
          setError(reason instanceof Error ? reason.message : 'Unable to check your session.')
        }
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false; window.removeEventListener('talged:session-expired', expired) }
  }, [sessionAttempt])

  async function login(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setShowPassword(false)
    setError('')
    try {
      const value = await signIn(email, password)
      setPassword('')
      setAuthUser(value)
      setUser(value)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to sign in.')
    } finally { setBusy(false) }
  }

  async function logout() {
    setBusy(true)
    setError('')
    try { await signOut(); setUser(null) }
    catch { setError('Unable to sign out. Please retry.') }
    finally { setBusy(false) }
  }

  if (loading) return <p style={{ padding: 32 }}>Checking your session…</p>
  if (user) return (
    <div key={user.id}>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <div className="account-bar" style={{ display: 'flex', gap: 16, alignItems: 'center', justifyContent: 'flex-end', padding: '10px 24px', background: 'var(--bg-surface)' }}>
        <span style={{ fontSize: 12 }}>{user.email}</span>
        <button onClick={logout} disabled={busy}>Sign out</button>
        {error && <span role="alert">{error}</span>}
      </div>
      {children}
    </div>
  )
  const fieldStyle = { display: 'block', width: '100%', marginTop: 8, marginBottom: 20, padding: 12, borderRadius: 8, border: '1px solid var(--border-strong)', color: 'var(--text-primary)', background: 'var(--bg-surface-2)' }
  return (
    <main className="auth-page" style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
      <form className="auth-card" onSubmit={login} style={{ width: '100%', maxWidth: 420, padding: 32, background: 'var(--bg-surface)', borderRadius: 20 }}>
        <Logo />
        <h1 style={{ marginTop: 32, marginBottom: 8, fontSize: 26, letterSpacing: '-0.03em' }}>Welcome back</h1>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>Use the account provided by your administrator.</p>
        <label htmlFor="email">Email</label>
        <input id="email" type="email" autoComplete="username" required maxLength={320} value={email} onChange={(event) => setEmail(event.target.value)} style={fieldStyle} />
        <label htmlFor="password">Password</label>
        <div className="password-field">
          <input id="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" required maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} style={{ ...fieldStyle, margin: 0, paddingRight: 56 }} />
          <button
            className="password-toggle"
            type="button"
            aria-label={showPassword ? 'Hide password' : 'Show password'}
            aria-controls="password"
            title={showPassword ? 'Hide password' : 'Show password'}
            onClick={() => setShowPassword(visible => !visible)}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z" />
              <circle cx="12" cy="12" r="3" />
              {showPassword && <path d="m3 3 18 18" />}
            </svg>
          </button>
        </div>
        {error && <p role="alert" style={{ color: '#fca5a5' }}>{error}</p>}
        {sessionUnavailable && <button type="button" onClick={() => { setError(''); setLoading(true); setSessionUnavailable(false); setSessionAttempt(value => value + 1) }} style={{ marginBottom: 16, padding: '10px 12px', color: 'var(--text-action)', border: '1px solid var(--border-strong)', borderRadius: 8, cursor: 'pointer' }}>Check connection again</button>}
        <button className="brand-primary" type="submit" disabled={busy} style={{ width: '100%', padding: 12, borderRadius: 8, border: 0, background: 'var(--accent-purple)', color: 'white', cursor: 'pointer' }}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Forgot your password? <a href="/reset-password">Reset password</a>. For account access, contact your administrator.</p>
      </form>
    </main>
  )
}
