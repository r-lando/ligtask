import type {
  AssessmentDetail,
  AssessmentHistoryResponse,
} from '../types/assessment'

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000'

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

export async function uploadRepository<T>(
  file: File,
): Promise<T> {
  const formData = new FormData()

  formData.append('file', file)

  const response = await fetch(
    `${API_BASE_URL}/assessments/upload`,
    {
      method: 'POST',
      body: formData,
    },
  )

  return parseResponse<T>(response)
}

export async function assessGitHubRepository<T>(
  repositoryUrl: string,
): Promise<T> {
  const response = await fetch(
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

  return parseResponse<T>(response)
}

export async function getAssessments(): Promise<AssessmentHistoryResponse> {
  const response = await fetch(
    `${API_BASE_URL}/assessments`,
  )

  return parseResponse<AssessmentHistoryResponse>(response)
}

export async function getAssessment(
  assessmentId: string,
): Promise<AssessmentDetail> {
  const response = await fetch(
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