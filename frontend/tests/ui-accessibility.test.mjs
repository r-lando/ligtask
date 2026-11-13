import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const load = path => readFile(new URL(`../src/${path}`, import.meta.url), 'utf8')

test('GitHub results show recorded commit or an honest legacy label', async () => {
  const results = await load('pages/AssessmentResultsScreen.tsx')
  assert.match(results, /assessment.input_type === 'GITHUB'/)
  assert.match(results, /Scanned Git commit/)
  assert.match(results, /assessment.source_revision\?\.commit_sha/)
  assert.match(results, /Not recorded \(older assessment\)/)
})

test('resumable scans distinguish connectivity errors from terminal failures', async () => {
  const app = await load('App.tsx')
  assert.match(app, /Connection interrupted/)
  assert.match(app, /Reconnect to assessment/)
  assert.match(app, /Boolean\(error && getPendingJob\(\)\)/)
  assert.match(await load('components/AuthGate.tsx'), /Check connection again/)
})

test('password visibility is opt-in with a named non-submit control', async () => {
  const auth = await load('components/AuthGate.tsx')
  assert.match(auth, /\[showPassword, setShowPassword\] = useState\(false\)/)
  assert.match(auth, /type=\{showPassword \? 'text' : 'password'\}/)
  assert.match(auth, /className="password-toggle"\s+type="button"/)
  assert.match(auth, /aria-label=\{showPassword \? 'Hide password' : 'Show password'\}/)
  assert.match(auth, /aria-controls="password"/)
  assert.match(auth, /setShowPassword\(false\)/)
})

test('chart graphics do not duplicate filter controls or severity color meanings', async () => {
  const results = await load('pages/AssessmentResultsScreen.tsx')
  assert.match(results, /aria-hidden="true"/)
  assert.match(results, /Select a severity below to filter/)
  for (const token of ['primary', 'secondary', 'tertiary', 'quaternary']) {
    assert.ok(results.includes(`var(--chart-${token})`))
  }
  assert.doesNotMatch(results, /linear-gradient\(135deg, #7c3aed, #3b82f6\)/)
  assert.match(results, /className="finding-row"/)
})

test('saved results offer a read-only retry and readable finding details', async () => {
  const results = await load('pages/AssessmentResultsScreen.tsx')
  assert.match(results, /\[assessmentId, retryAttempt\]/)
  assert.match(results, /setRetryAttempt\(value => value \+ 1\)/)
  assert.match(results, /role="status">Loading assessment results/)
  assert.match(results, /overflowWrap: 'anywhere'/)
  const details = await load('pages/FindingDetailScreen.tsx')
  assert.match(details, /title="What was found"/)
  assert.match(details, /title="What to check or fix"/)
  assert.match(details, /title="Original scanner message"/)
})

test('repository input and upload retain keyboard-accessible names and activation', async () => {
  const app = await load('App.tsx')
  assert.match(app, /htmlFor="repository-url"/)
  assert.match(app, /id="repository-url"/)
  assert.match(app, /role="button"\s+tabIndex=\{0\}/)
  assert.match(app, /event.key === 'Enter' \|\| event.key === ' '/)
  assert.match(app, /aria-label=\{selectedFile \? 'Replace repository ZIP file'/)
})

test('navigation and filter states are exposed beyond color', async () => {
  assert.match(await load('components/Sidebar.tsx'), /aria-current=\{active \? 'page'/)
  const results = await load('pages/AssessmentResultsScreen.tsx')
  assert.match(results, /aria-pressed=\{isSelected\}/)
  assert.match(results, /noCoverage \? 'Not checked'/)
})

test('responsive and motion alternatives remain in shared styles', async () => {
  const css = await load('index.css')
  assert.match(css, /max-width: 700px/)
  assert.match(css, /--grid-six: repeat\(2/)
  assert.match(css, /role="button".*focus-visible/)
  assert.doesNotMatch(css, /animation-duration: \.01ms/)
})

test('secondary text token meets normal text contrast on dark surfaces', async () => {
  const css = await load('index.css')
  const muted = css.match(/--text-muted:\s*#([0-9a-f]{6})/)[1]
  const luminance = hex => {
    const [r,g,b] = hex.match(/../g).map(c => parseInt(c,16)/255).map(c => c <= .04045 ? c/12.92 : ((c+.055)/1.055)**2.4)
    return .2126*r+.7152*g+.0722*b
  }
  for (const background of ['0c0a14', '13101e', '1b1629', '241c35']) {
    assert.ok((luminance(muted)+.05)/(luminance(background)+.05) >= 4.5)
  }
})
