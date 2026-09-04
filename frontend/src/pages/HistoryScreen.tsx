import { useEffect, useState } from 'react'
import { getAssessments } from '../services/api'
import type { AssessmentHistoryItem } from '../types/assessment'
import type { Screen } from '../components/Sidebar'

interface HistoryScreenProps {
  navigate: (screen: Screen) => void
  onOpenAssessment: (assessmentId: string) => void
}

function formatDate(value: string) {
  const date = new Date(value)

  return new Intl.DateTimeFormat('en-PH', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date)
}

function formatDuration(milliseconds: number) {
  if (milliseconds < 1000) {
    return `${milliseconds} ms`
  }

  return `${(milliseconds / 1000).toFixed(1)} s`
}

function getHighestSeverity(
  assessment: AssessmentHistoryItem,
): string {
  const summary = assessment.severity_summary

  if (summary.CRITICAL > 0) return 'CRITICAL'
  if (summary.HIGH > 0) return 'HIGH'
  if (summary.MEDIUM > 0) return 'MEDIUM'
  if (summary.LOW > 0) return 'LOW'
  if (summary.INFO > 0) return 'INFO'

  return 'NONE'
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'CRITICAL':
      return '#dc2626'

    case 'HIGH':
      return '#f97316'

    case 'MEDIUM':
      return '#eab308'

    case 'LOW':
      return '#22c55e'

    case 'INFO':
      return '#3b82f6'

    default:
      return '#64748b'
  }
}


function getAssessmentStatusLabel(status: string) {
  switch (status) {
    case 'completed':
      return 'Completed'

    case 'partial':
      return 'Partial'

    case 'failed':
      return 'Failed'

    default:
      return status
        .replaceAll('_', ' ')
        .replace(/\b\w/g, (character) =>
          character.toUpperCase(),
        )
  }
}

function getAssessmentStatusColor(status: string) {
  switch (status) {
    case 'completed':
      return '#22c55e'

    case 'partial':
      return '#f59e0b'

    case 'failed':
      return '#ef4444'

    default:
      return '#94a3b8'
  }
}

function getAssessmentStatusBackground(status: string) {
  switch (status) {
    case 'completed':
      return 'rgba(34,197,94,0.10)'

    case 'partial':
      return 'rgba(245,158,11,0.10)'

    case 'failed':
      return 'rgba(239,68,68,0.10)'

    default:
      return 'rgba(148,163,184,0.10)'
  }
}

export default function HistoryScreen({
  navigate,
  onOpenAssessment,
}: HistoryScreenProps) {
  const [assessments, setAssessments] = useState<
    AssessmentHistoryItem[]
  >([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let active = true

    async function loadAssessments() {
      try {
        setLoading(true)
        setError(null)

        const data = await getAssessments()

        if (!active) return

        setAssessments(data.assessments)
      } catch (err) {
        if (!active) return

        setError(
          err instanceof Error
            ? err.message
            : 'Unable to load assessment history.',
        )
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadAssessments()

    return () => {
      active = false
    }
  }, [])

  return (
    <div
      style={{
        flex: 1,
        padding: '40px 48px',
        overflowY: 'auto',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 20,
          marginBottom: 28,
        }}
      >
        <div>
          <h1
            style={{
              fontSize: 22,
              fontWeight: 700,
              color: '#e2e8f0',
              margin: '0 0 6px',
            }}
          >
            Scan History
          </h1>

          <p
            style={{
              fontSize: 12,
              color: '#64748b',
              margin: 0,
            }}
          >
            Review previous repository security assessments and their completion status.
          </p>
        </div>

        <button
          type="button"
          onClick={() => navigate('repo')}
          style={{
            border: 'none',
            borderRadius: 8,
            padding: '9px 14px',
            cursor: 'pointer',
            color: '#ffffff',
            fontSize: 12,
            fontWeight: 600,
            background:
              'linear-gradient(135deg, #7c3aed, #3b82f6)',
          }}
        >
          New Assessment
        </button>
      </div>

      {loading && (
        <div
          style={{
            padding: 24,
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            color: '#94a3b8',
            fontSize: 13,
          }}
        >
          Loading assessment history...
        </div>
      )}

      {!loading && error && (
        <div
          style={{
            padding: 18,
            borderRadius: 10,
            border: '1px solid rgba(239,68,68,0.25)',
            background: 'rgba(239,68,68,0.06)',
            color: '#fca5a5',
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      {!loading && !error && assessments.length === 0 && (
        <div
          style={{
            padding: 30,
            borderRadius: 12,
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            textAlign: 'center',
          }}
        >
          <div
            style={{
              color: '#e2e8f0',
              fontWeight: 600,
              marginBottom: 6,
            }}
          >
            No assessments yet
          </div>

          <div
            style={{
              color: '#64748b',
              fontSize: 12,
              marginBottom: 16,
            }}
          >
            Submit a ZIP repository or public GitHub repository to
            begin an assessment.
          </div>

          <button
            type="button"
            onClick={() => navigate('repo')}
            style={{
              border: 'none',
              borderRadius: 8,
              padding: '9px 14px',
              cursor: 'pointer',
              color: '#ffffff',
              fontSize: 12,
              fontWeight: 600,
              background:
                'linear-gradient(135deg, #7c3aed, #3b82f6)',
            }}
          >
            Start Assessment
          </button>
        </div>
      )}

      {!loading && !error && assessments.length > 0 && (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 12,
          }}
        >
          {assessments.map((assessment) => {
            const severity = getHighestSeverity(assessment)

            return (
              <button
                type="button"
                key={assessment.assessment_id}
                onClick={() =>
                  onOpenAssessment(assessment.assessment_id)
                }
                style={{
                  width: '100%',
                  textAlign: 'left',
                  border:
                    assessment.status === 'partial'
                      ? '1px solid rgba(245,158,11,0.28)'
                      : assessment.status === 'failed'
                        ? '1px solid rgba(239,68,68,0.28)'
                        : '1px solid var(--border)',
                  background: 'var(--bg-surface)',
                  borderRadius: 12,
                  padding: '18px 20px',
                  cursor: 'pointer',
                  fontFamily: 'inherit',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    gap: 20,
                  }}
                >
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 10,
                        marginBottom: 7,
                      }}
                    >
                      <span
                        style={{
                          color: '#e2e8f0',
                          fontSize: 14,
                          fontWeight: 700,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {assessment.repository_name}
                      </span>

                      <span
                        style={{
                          padding: '3px 7px',
                          borderRadius: 5,
                          background:
                            assessment.input_type === 'GITHUB'
                              ? 'rgba(59,130,246,0.1)'
                              : 'rgba(124,58,237,0.1)',
                          color:
                            assessment.input_type === 'GITHUB'
                              ? '#60a5fa'
                              : '#a78bfa',
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: '0.04em',
                        }}
                      >
                        {assessment.input_type}
                      </span>


                      <span
                        style={{
                          padding: '3px 7px',
                          borderRadius: 999,
                          background:
                            getAssessmentStatusBackground(
                              assessment.status,
                            ),
                          color:
                            getAssessmentStatusColor(
                              assessment.status,
                            ),
                          fontSize: 9,
                          fontWeight: 700,
                          letterSpacing: '0.04em',
                          textTransform: 'uppercase',
                        }}
                      >
                        {getAssessmentStatusLabel(
                          assessment.status,
                        )}
                      </span>
                    </div>

                    <div
                      style={{
                        color: '#64748b',
                        fontSize: 11,
                      }}
                    >
                      {formatDate(assessment.created_at)}
                    </div>
                  </div>

                  <div
                    style={{
                      minWidth: 90,
                      textAlign: 'right',
                    }}
                  >
                    <div
                      style={{
                        color: getSeverityColor(severity),
                        fontSize: 11,
                        fontWeight: 700,
                        marginBottom: 4,
                      }}
                    >
                      {severity === 'NONE'
                        ? 'No Findings'
                        : severity}
                    </div>

                    <div
                      style={{
                        color: '#64748b',
                        fontSize: 10,
                      }}
                    >
                      Highest severity
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns:
                      'repeat(4, minmax(0, 1fr))',
                    gap: 12,
                    marginTop: 18,
                    paddingTop: 14,
                    borderTop: '1px solid var(--border)',
                  }}
                >
                  <div>
                    <div
                      style={{
                        color: '#64748b',
                        fontSize: 9,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: 4,
                      }}
                    >
                      Findings
                    </div>

                    <div
                      style={{
                        color: '#e2e8f0',
                        fontSize: 13,
                        fontWeight: 600,
                      }}
                    >
                      {assessment.consolidated_findings_count}
                    </div>
                  </div>

                  <div>
                    <div
                      style={{
                        color: '#64748b',
                        fontSize: 9,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: 4,
                      }}
                    >
                      Files
                    </div>

                    <div
                      style={{
                        color: '#e2e8f0',
                        fontSize: 13,
                        fontWeight: 600,
                      }}
                    >
                      {assessment.total_files}
                    </div>
                  </div>

                  <div>
                    <div
                      style={{
                        color: '#64748b',
                        fontSize: 9,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: 4,
                      }}
                    >
                      Processing
                    </div>

                    <div
                      style={{
                        color: '#e2e8f0',
                        fontSize: 13,
                        fontWeight: 600,
                      }}
                    >
                      {formatDuration(
                        assessment.processing_time_ms,
                      )}
                    </div>
                  </div>

                  <div>
                    <div
                      style={{
                        color: '#64748b',
                        fontSize: 9,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: 4,
                      }}
                    >
                      Status
                    </div>

                    <div
                      style={{
                        color:
                          getAssessmentStatusColor(
                            assessment.status,
                          ),
                        fontSize: 13,
                        fontWeight: 600,
                      }}
                    >
                      {getAssessmentStatusLabel(
                        assessment.status,
                      )}
                    </div>
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}