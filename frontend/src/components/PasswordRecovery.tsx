import { useState, type FormEvent, type ReactNode } from 'react'
import { requestPasswordRecovery, resetPassword } from '../services/api'
import Logo from './Logo'

// Capture once before React StrictMode mounts. Never persist credentials.
const parameters = new URLSearchParams(window.location.hash.slice(1))
let recoveryToken = parameters.get('type') === 'recovery' ? parameters.get('access_token') : null
const recoveryError = parameters.has('error') || parameters.has('error_code')
const recoveryRoute = window.location.pathname === '/reset-password' || parameters.get('type') === 'recovery' || recoveryError
if (recoveryRoute && window.location.hash) window.history.replaceState(null, '', '/reset-password')

export default function PasswordRecovery({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<'request' | 'reset' | 'done'>(recoveryToken ? 'reset' : 'request')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState(recoveryError ? 'This link has expired or was already used. Request a new link below.' : '')
  if (!recoveryRoute) return children

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError(''); setMessage('')
    if (mode === 'reset' && password !== confirmation) { setError('The passwords do not match.'); return }
    setBusy(true)
    try {
      if (mode === 'request') {
        const result = await requestPasswordRecovery(email)
        setMessage(result.message)
      } else if (recoveryToken) {
        const result = await resetPassword(recoveryToken, password)
        recoveryToken = null
        setPassword(''); setConfirmation(''); setMode('done'); setMessage(result.message)
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to complete password recovery. Please retry.')
    } finally { setBusy(false) }
  }
  const fieldStyle = { display: 'block', width: '100%', margin: '8px 0 20px', padding: 12, borderRadius: 8, border: '1px solid var(--border-strong)', color: 'var(--text-primary)', background: 'var(--bg-surface-2)' }
  return <main className="auth-page" style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
    <form className="auth-card" onSubmit={submit} style={{ width: '100%', maxWidth: 420, padding: 32, background: 'var(--bg-surface)', borderRadius: 20 }}>
      <Logo />
      <h1 style={{ marginTop: 32, fontSize: 26 }}>{mode === 'reset' ? 'Set a new password' : mode === 'done' ? 'Password updated' : 'Reset your password'}</h1>
      {mode === 'request' && <><p>Enter the email you use for TALGED.</p><label htmlFor="recovery-email">Email</label><input id="recovery-email" type="email" autoComplete="username" required maxLength={320} value={email} onChange={e => setEmail(e.target.value)} style={fieldStyle} /></>}
      {mode === 'reset' && <><p>Use at least 12 characters.</p><label htmlFor="new-password">New password</label><input id="new-password" type="password" autoComplete="new-password" minLength={12} maxLength={1024} required value={password} onChange={e => setPassword(e.target.value)} style={fieldStyle} /><label htmlFor="confirm-password">Confirm new password</label><input id="confirm-password" type="password" autoComplete="new-password" minLength={12} maxLength={1024} required value={confirmation} onChange={e => setConfirmation(e.target.value)} style={fieldStyle} /></>}
      {error && <p role="alert" style={{ color: '#fca5a5' }}>{error}</p>}
      {message && <p role="status">{message}</p>}
      {mode !== 'done' && <button className="brand-primary" type="submit" disabled={busy} style={{ width: '100%', padding: 12, borderRadius: 8, border: 0, background: 'var(--accent-purple)', color: 'white', cursor: 'pointer' }}>{busy ? 'Please wait…' : mode === 'reset' ? 'Save new password' : 'Send reset link'}</button>}
      {mode === 'reset' && <button type="button" disabled={busy} onClick={() => { recoveryToken = null; setPassword(''); setConfirmation(''); setError(''); setMode('request') }} style={{ marginTop: 16 }}>Request a new link</button>}
      <p><a href="/" onClick={() => { recoveryToken = null }}>Back to sign in</a></p>
    </form>
  </main>
}
