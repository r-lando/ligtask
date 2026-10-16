import { beforeEach, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { stripTypeScriptTypes } from 'node:module'

// Exercise the browser service directly; substitute Vite's build-time env.
const source = await readFile(new URL('../src/services/api.ts', import.meta.url), 'utf8')
const compiled = stripTypeScriptTypes(source).replaceAll('import.meta.env', '({})')
const api = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)

beforeEach(() => {
  const values = new Map()
  globalThis.sessionStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  }
  globalThis.window = {
    setTimeout: (callback) => setTimeout(callback, 0),
    clearTimeout,
    dispatchEvent: () => {},
  }
  api.setAuthUser(null)
})

const response = (job) => Response.json(job)
const queued = { job_id: 'job-1', status: 'queued', assessment_id: null, error: null }

test('submission returns queued job immediately and remembers it', async () => {
  globalThis.fetch = async (url, options) => {
    assert.match(url, /\/assessments\/github$/)
    assert.equal(JSON.parse(options.body).repository_url, 'https://github.com/a/b')
    return response(queued)
  }
  assert.deepEqual(await api.assessGitHubRepository('https://github.com/a/b'), queued)
  assert.equal(api.getPendingJob(), 'job-1')
})

test('polling reports queue states and opens the completed assessment', async () => {
  const statuses = []
  const jobs = [queued, { ...queued, status: 'running' }, {
    ...queued, status: 'completed', assessment_id: 'assessment-1',
  }]
  globalThis.fetch = async () => response(jobs.shift())
  const result = await api.waitForAssessment('job-1', (status) => statuses.push(status))
  assert.deepEqual(result, { assessment_id: 'assessment-1' })
  assert.deepEqual(statuses, ['queued', 'running', 'completed'])
  assert.equal(api.getPendingJob(), null)
})

test('network failure keeps job available for reconnection', async () => {
  globalThis.fetch = async () => { throw new Error('offline') }
  await assert.rejects(api.waitForAssessment('job-1', () => {}), /offline/)
  assert.equal(api.getPendingJob(), 'job-1')
})

test('failed job exposes its safe error and clears pending state', async () => {
  globalThis.fetch = async () => response({ ...queued, status: 'failed', error: 'Scanner timed out.' })
  await assert.rejects(api.waitForAssessment('job-1', () => {}), /Scanner timed out/)
  assert.equal(api.getPendingJob(), null)
})

test('unmount aborts polling without discarding the resumable job', async () => {
  const controller = new AbortController()
  globalThis.fetch = async () => response(queued)
  const waiting = api.waitForAssessment('job-1', () => controller.abort(), controller.signal)
  await assert.rejects(waiting, { name: 'AbortError' })
  assert.equal(api.getPendingJob(), 'job-1')
})

test('API calls include session cookies and refresh before retrying expired requests', async () => {
  const calls = []
  globalThis.fetch = async (url, options) => {
    calls.push(url)
    assert.equal(options.credentials, 'include')
    if (calls.length === 1) return Response.json({ detail: 'Session expired.' }, { status: 401 })
    if (url.endsWith('/auth/refresh')) return response({ id: 'alice', email: 'alice@example.com' })
    return response({ total: 0, assessments: [] })
  }
  assert.equal((await api.getAssessments()).total, 0)
  assert.deepEqual(calls.map((url) => new URL(url).pathname), [
    '/assessments', '/auth/refresh', '/assessments',
  ])
})

test('pending job references are isolated between users', async () => {
  api.setAuthUser({ id: 'alice', email: 'alice@example.com' })
  globalThis.fetch = async () => response(queued)
  await api.assessGitHubRepository('https://github.com/a/b')
  api.setAuthUser({ id: 'bob', email: 'bob@example.com' })
  assert.equal(api.getPendingJob(), null)
  api.setAuthUser({ id: 'alice', email: 'alice@example.com' })
  assert.equal(api.getPendingJob(), 'job-1')
})

test('signing out aborts active polling', async () => {
  api.setAuthUser({ id: 'alice', email: 'alice@example.com' })
  globalThis.fetch = async () => response(queued)
  const waiting = api.waitForAssessment('job-1', () => { api.setAuthUser(null) })
  await assert.rejects(waiting, { name: 'AbortError' })
})

test('unauthenticated sessions notify the login gate without retrying forever', async () => {
  let expired = false
  window.dispatchEvent = (event) => { expired = event.type === 'talged:session-expired' }
  let calls = 0
  globalThis.fetch = async () => {
    calls++
    return Response.json({ detail: 'Please sign in.' }, { status: 401 })
  }
  await assert.rejects(api.getAssessments(), /Please sign in/)
  assert.equal(expired, true)
  assert.equal(calls, 2)
})

test('stale requests cannot retry under another signed-in user', async () => {
  api.setAuthUser({ id: 'alice', email: 'alice@example.com' })
  globalThis.fetch = async () => {
    api.setAuthUser({ id: 'bob', email: 'bob@example.com' })
    return Response.json({ detail: 'Session expired.' }, { status: 401 })
  }
  await assert.rejects(api.getAssessments(), { name: 'AbortError' })
})
