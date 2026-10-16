import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { ApiError, getCurrentUser, setAuthUser, signIn, signOut, type AuthUser } from '../services/api'

export default function AuthGate({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

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
          setError(reason instanceof Error ? reason.message : 'Unable to check your session.')
        }
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false; window.removeEventListener('talged:session-expired', expired) }
  }, [])

  async function login(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
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
      <div style={{ display: 'flex', gap: 16, alignItems: 'center', justifyContent: 'flex-end', padding: '10px 24px', background: 'var(--bg-surface)' }}>
        <span style={{ fontSize: 12 }}>{user.email}</span>
        <button onClick={logout} disabled={busy}>Sign out</button>
        {error && <span role="alert">{error}</span>}
      </div>
      {children}
    </div>
  )
  const fieldStyle = { display: 'block', width: '100%', marginTop: 8, marginBottom: 20, padding: 12, borderRadius: 8, border: '1px solid var(--border-strong)', color: 'var(--text-primary)', background: 'var(--bg-surface-2)' }
  return (
    <main style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
      <form onSubmit={login} style={{ width: '100%', maxWidth: 400, padding: 32, background: 'var(--bg-surface)', borderRadius: 16 }}>
        <h1 style={{ marginTop: 0 }}>Sign in to TALGED</h1>
        <p style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>Use the account provided by your administrator.</p>
        <label htmlFor="email">Email</label>
        <input id="email" type="email" autoComplete="username" required maxLength={320} value={email} onChange={(event) => setEmail(event.target.value)} style={fieldStyle} />
        <label htmlFor="password">Password</label>
        <input id="password" type="password" autoComplete="current-password" required maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} style={fieldStyle} />
        {error && <p role="alert" style={{ color: '#fca5a5' }}>{error}</p>}
        <button type="submit" disabled={busy} style={{ width: '100%', padding: 12, borderRadius: 8, border: 0, background: '#7c3aed', color: 'white', cursor: 'pointer' }}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Need access or a password reset? Contact your administrator.</p>
      </form>
    </main>
  )
}
