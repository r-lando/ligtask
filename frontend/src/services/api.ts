import type {
  AssessmentDetail,
  AssessmentHistoryResponse,
} from '../types/assessment'

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'

export type AssessmentJob = {
  job_id: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  assessment_id: string | null
  error: string | null
}

export type AuthUser = { id: string; email: string }
let currentUser: AuthUser | null = null
let sessionController = new AbortController()
let refreshing: Promise<Response> | null = null

function pendingJobKey() {
  return `talged.pendingJob:${API_BASE_URL}:${currentUser?.id ?? 'anonymous'}`
}

export function setAuthUser(user: AuthUser | null) {
  if (user?.id !== currentUser?.id) {
    sessionController.abort()
    sessionController = new AbortController()
  }
  currentUser = user
}

async function apiFetch(url: string, options?: RequestInit): Promise<Response> {
  const signal = options?.signal
    ? AbortSignal.any([options.signal, sessionController.signal])
    : sessionController.signal
  const requestOptions = { ...options, signal, credentials: 'include' as const }
  let response = await fetch(url, requestOptions)
  signal.throwIfAborted()
  if (response.status === 401) {
    refreshing ??= fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST', credentials: 'include',
    }).finally(() => { refreshing = null })
    const refreshed = await refreshing
    signal.throwIfAborted()
    if (refreshed.ok) response = await fetch(url, requestOptions)
    else if (refreshed.status === 401) {
      window.dispatchEvent(new Event('talged:session-expired'))
    } else {
      return refreshed
    }
  }
  signal.throwIfAborted()
  return response
}

export async function getCurrentUser(): Promise<AuthUser> {
  return parseResponse<AuthUser>(await apiFetch(`${API_BASE_URL}/auth/me`))
}

export async function signIn(email: string, password: string): Promise<AuthUser> {
  return parseResponse<AuthUser>(await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  }))
}

export async function signOut(): Promise<void> {
  await parseResponse(await fetch(`${API_BASE_URL}/auth/logout`, {
    method: 'POST', credentials: 'include',
  }))
  setAuthUser(null)
}

export function getPendingJob(): string | null {
  try { return sessionStorage.getItem(pendingJobKey()) } catch { return null }
}

function rememberJob(jobId: string | null, key = pendingJobKey()) {
  try {
    if (jobId) sessionStorage.setItem(key, jobId)
    else sessionStorage.removeItem(key)
  } catch { /* Scanning also works when browser storage is disabled. */ }
}

export async function waitForAssessment(
  jobId: string,
  onStatus: (status: AssessmentJob['status']) => void,
  signal?: AbortSignal,
): Promise<{ assessment_id: string }> {
  signal = signal ? AbortSignal.any([signal, sessionController.signal]) : sessionController.signal
  const storageKey = pendingJobKey()
  rememberJob(jobId, storageKey)
  while (true) {
    signal?.throwIfAborted()
    const response = await apiFetch(
      `${API_BASE_URL}/assessments/jobs/${encodeURIComponent(jobId)}`,
      { signal, cache: 'no-store' },
    )
    if (response.status === 404) rememberJob(null, storageKey)
    const job = await parseResponse<AssessmentJob>(response)
    signal?.throwIfAborted()
    onStatus(job.status)
    if (job.status === 'failed') {
      rememberJob(null, storageKey)
      throw new Error(job.error || 'Assessment failed. Please retry.')
    }
    if (job.status === 'completed') {
      rememberJob(null, storageKey)
      if (!job.assessment_id) throw new Error('Assessment result is unavailable.')
      return { assessment_id: job.assessment_id }
    }
    signal?.throwIfAborted()
    await new Promise<void>((resolve, reject) => {
      const onAbort = () => {
        clearTimeout(timer)
        reject(signal?.reason)
      }
      const timer = window.setTimeout(() => {
        signal?.removeEventListener('abort', onAbort)
        resolve()
      }, 1500)
      signal?.addEventListener('abort', onAbort, { once: true })
    })
  }
}

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`

    try {
      const data = await response.json()

      if (typeof data?.detail === 'string') {
        message = data.detail
      }
    } catch {
      // Keep the default error message.
    }

    throw new ApiError(message, response.status)
  }

  return response.json() as Promise<T>
}

export async function uploadRepository(
  file: File,
): Promise<AssessmentJob> {
  const formData = new FormData()

  formData.append('file', file)

  const response = await apiFetch(
    `${API_BASE_URL}/assessments/upload`,
    {
      method: 'POST',
      body: formData,
    },
  )

  const job = await parseResponse<AssessmentJob>(response)
  rememberJob(job.job_id)
  return job
}

export async function assessGitHubRepository(
  repositoryUrl: string,
): Promise<AssessmentJob> {
  const response = await apiFetch(
    `${API_BASE_URL}/assessments/github`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        repository_url: repositoryUrl,
      }),
    },
  )

  const job = await parseResponse<AssessmentJob>(response)
  rememberJob(job.job_id)
  return job
}

export async function getAssessments(): Promise<AssessmentHistoryResponse> {
  const response = await apiFetch(
    `${API_BASE_URL}/assessments`,
  )

  return parseResponse<AssessmentHistoryResponse>(response)
}

export async function getAssessment(
  assessmentId: string,
): Promise<AssessmentDetail> {
  const response = await apiFetch(
    `${API_BASE_URL}/assessments/${encodeURIComponent(
      assessmentId,
    )}`,
  )

  return parseResponse<AssessmentDetail>(response)
}

export function getHtmlReportUrl(
  assessmentId: string,
): string {
  return `${API_BASE_URL}/assessments/${encodeURIComponent(
    assessmentId,
  )}/report`
}

export function getPdfReportUrl(
  assessmentId: string,
): string {
  return `${API_BASE_URL}/assessments/${encodeURIComponent(
    assessmentId,
  )}/report.pdf`
}

export async function downloadReport(assessmentId: string, format: 'html' | 'pdf'): Promise<void> {
  const response = await apiFetch(format === 'pdf' ? getPdfReportUrl(assessmentId) : getHtmlReportUrl(assessmentId))
  if (!response.ok) await parseResponse(response)
  const url = URL.createObjectURL(await response.blob())
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `talged-assessment-${assessmentId}.${format}`
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000)
}
