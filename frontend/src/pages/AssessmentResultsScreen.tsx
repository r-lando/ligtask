import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react'

import {
  getAssessment,
  getHtmlReportUrl,
  getPdfReportUrl,
} from '../services/api'

import type {
  AssessmentDetail,
  AssessmentFinding,
  FindingSeverity,
} from '../types/assessment'

import type { Screen } from '../components/Sidebar'


interface AssessmentResultsScreenProps {
  assessmentId: string
  navigate: (screen: Screen) => void
  onOpenFinding: (finding: AssessmentFinding) => void
}


const severityOrder: FindingSeverity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
  'UNKNOWN',
]


function severityColor(
  severity: FindingSeverity,
) {
  switch (severity) {
    case 'CRITICAL':
      return '#ef4444'

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


function formatDate(value: string) {
  return new Intl.DateTimeFormat('en-PH', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(value))
}


function formatDuration(
  milliseconds: number,
) {
  return `${(milliseconds / 1000).toFixed(1)} s`
}


function SeverityBadge({
  severity,
}: {
  severity: FindingSeverity
}) {
  const color = severityColor(severity)

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '4px 8px',
        borderRadius: 5,
        background: `${color}18`,
        color,
        fontSize: 9,
        fontWeight: 700,
        letterSpacing: '0.04em',
      }}
    >
      {severity}
    </span>
  )
}


export default function AssessmentResultsScreen({
  assessmentId,
  navigate,
  onOpenFinding,
}: AssessmentResultsScreenProps) {
  const pageRef =
    useRef<HTMLDivElement | null>(null)

  const [assessment, setAssessment] =
    useState<AssessmentDetail | null>(null)

  const [loading, setLoading] =
    useState(true)

  const [error, setError] =
    useState<string | null>(null)

  const [
    severityFilter,
    setSeverityFilter,
  ] = useState<FindingSeverity | 'ALL'>(
    'ALL',
  )


  /*
   * Reset the Results page whenever it is mounted.
   *
   * This handles both possible scroll containers:
   * 1. the browser/document
   * 2. this page's own scrolling container
   *
   * Therefore:
   *
   * Results
   *   -> scroll down
   *   -> Finding Details
   *   -> Back
   *
   * returns to the TOP of Assessment Results.
   */
  useLayoutEffect(() => {
    window.scrollTo({
      top: 0,
      left: 0,
      behavior: 'auto',
    })

    if (pageRef.current) {
      pageRef.current.scrollTo({
        top: 0,
        left: 0,
        behavior: 'auto',
      })
    }
  }, [assessmentId])


  useEffect(() => {
    let active = true

    async function loadAssessment() {
      try {
        setLoading(true)
        setError(null)

        const data =
          await getAssessment(
            assessmentId,
          )

        if (!active) {
          return
        }

        setAssessment(data)
      } catch (err) {
        if (!active) {
          return
        }

        setError(
          err instanceof Error
            ? err.message
            : 'Unable to load assessment.',
        )
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    loadAssessment()

    return () => {
      active = false
    }
  }, [assessmentId])


  if (loading) {
    return (
      <div
        style={{
          padding: '40px 48px',
        }}
      >
        <div
          style={{
            padding: 24,
            background:
              'var(--bg-surface)',
            border:
              '1px solid var(--border)',
            borderRadius: 12,
            color: '#94a3b8',
            fontSize: 13,
          }}
        >
          Loading assessment results...
        </div>
      </div>
    )
  }


  if (error || !assessment) {
    return (
      <div
        style={{
          padding: '40px 48px',
        }}
      >
        <button
          type="button"
          onClick={() =>
            navigate('history')
          }
          style={{
            background: 'none',
            border: 'none',
            color: '#7c3aed',
            cursor: 'pointer',
            marginBottom: 20,
          }}
        >
          ← Back to Scan History
        </button>

        <div
          style={{
            padding: 20,
            borderRadius: 10,
            border:
              '1px solid rgba(239,68,68,0.25)',
            background:
              'rgba(239,68,68,0.06)',
            color: '#fca5a5',
            fontSize: 13,
          }}
        >
          {error ??
            'Assessment could not be found.'}
        </div>
      </div>
    )
  }


  const filteredFindings =
    severityFilter === 'ALL'
      ? assessment.findings
      : assessment.findings.filter(
          (finding) =>
            finding.severity ===
            severityFilter,
        )


  const totalFindings =
    assessment.consolidated_findings_count


  return (
    <div
      ref={pageRef}
      style={{
        flex: 1,
        padding: '36px 48px 48px',
        overflowY: 'auto',
      }}
    >
      <button
        type="button"
        onClick={() =>
          navigate('history')
        }
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          background: 'none',
          border: 'none',
          color: '#7c3aed',
          cursor: 'pointer',
          fontSize: 12,
          fontWeight: 500,
          padding: 0,
          marginBottom: 20,
        }}
      >
        ← Back to Scan History
      </button>


      <div
        style={{
          display: 'flex',
          justifyContent:
            'space-between',
          alignItems: 'flex-start',
          gap: 24,
          marginBottom: 24,
        }}
      >
        <div
          style={{
            minWidth: 0,
          }}
        >
          <h1
            style={{
              fontSize: 22,
              fontWeight: 700,
              color: '#e2e8f0',
              margin: '0 0 7px',
            }}
          >
            Assessment Results
          </h1>

          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: 8,
              alignItems: 'center',
            }}
          >
            <span
              style={{
                color: '#94a3b8',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {
                assessment.repository_name
              }
            </span>

            <span
              style={{
                color: '#334155',
              }}
            >
              •
            </span>

            <span
              style={{
                color: '#64748b',
                fontSize: 11,
              }}
            >
              {assessment.input_type}
            </span>

            <span
              style={{
                color: '#334155',
              }}
            >
              •
            </span>

            <span
              style={{
                color: '#64748b',
                fontSize: 11,
              }}
            >
              {formatDate(
                assessment.created_at,
              )}
            </span>
          </div>
        </div>


        <div
          style={{
            display: 'flex',
            gap: 8,
            flexShrink: 0,
          }}
        >
          <button
            type="button"
            onClick={() =>
              window.open(
                getHtmlReportUrl(
                  assessment.assessment_id,
                ),
                '_blank',
                'noopener,noreferrer',
              )
            }
            style={{
              border:
                '1px solid var(--border)',
              background:
                'var(--bg-surface)',
              color: '#94a3b8',
              borderRadius: 8,
              padding: '8px 12px',
              cursor: 'pointer',
              fontSize: 11,
              fontWeight: 600,
            }}
          >
            HTML Report
          </button>

          <button
            type="button"
            onClick={() => {
              window.location.href =
                getPdfReportUrl(
                  assessment.assessment_id,
                )
            }}
            style={{
              border: 'none',
              background:
                'linear-gradient(135deg, #7c3aed, #3b82f6)',
              color: '#ffffff',
              borderRadius: 8,
              padding: '8px 12px',
              cursor: 'pointer',
              fontSize: 11,
              fontWeight: 600,
            }}
          >
            Download PDF
          </button>
        </div>
      </div>


      <div
        style={{
          display: 'grid',
          gridTemplateColumns:
            'repeat(4, minmax(0, 1fr))',
          gap: 12,
          marginBottom: 24,
        }}
      >
        {[
          {
            label:
              'Consolidated Findings',
            value: totalFindings,
          },
          {
            label: 'Raw Findings',
            value:
              assessment.raw_findings_count,
          },
          {
            label: 'Files Assessed',
            value:
              assessment.total_files,
          },
          {
            label: 'Processing Time',
            value: formatDuration(
              assessment.processing_time_ms,
            ),
          },
        ].map((item) => (
          <div
            key={item.label}
            style={{
              padding: '16px 18px',
              borderRadius: 10,
              background:
                'var(--bg-surface)',
              border:
                '1px solid var(--border)',
            }}
          >
            <div
              style={{
                color: '#64748b',
                fontSize: 9,
                fontWeight: 600,
                textTransform:
                  'uppercase',
                letterSpacing:
                  '0.05em',
                marginBottom: 7,
              }}
            >
              {item.label}
            </div>

            <div
              style={{
                color: '#e2e8f0',
                fontSize: 22,
                fontWeight: 700,
              }}
            >
              {item.value}
            </div>
          </div>
        ))}
      </div>


      <div
        style={{
          padding: 18,
          borderRadius: 10,
          background:
            'var(--bg-surface)',
          border:
            '1px solid var(--border)',
          marginBottom: 24,
        }}
      >
        <div
          style={{
            color: '#94a3b8',
            fontSize: 11,
            fontWeight: 600,
            marginBottom: 14,
          }}
        >
          Severity Distribution
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'repeat(6, minmax(0, 1fr))',
            gap: 10,
          }}
        >
          {severityOrder.map(
            (severity) => {
              const count =
                assessment
                  .severity_summary[
                  severity
                ]

              return (
                <button
                  type="button"
                  key={severity}
                  onClick={() =>
                    setSeverityFilter(
                      severityFilter ===
                        severity
                        ? 'ALL'
                        : severity,
                    )
                  }
                  style={{
                    padding:
                      '12px 10px',
                    borderRadius: 8,
                    cursor: 'pointer',
                    textAlign: 'left',
                    fontFamily:
                      'inherit',
                    background:
                      severityFilter ===
                      severity
                        ? `${severityColor(
                            severity,
                          )}12`
                        : 'var(--bg-surface-2)',
                    border:
                      severityFilter ===
                      severity
                        ? `1px solid ${severityColor(
                            severity,
                          )}55`
                        : '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      color:
                        severityColor(
                          severity,
                        ),
                      fontSize: 18,
                      fontWeight: 700,
                      marginBottom: 3,
                    }}
                  >
                    {count}
                  </div>

                  <div
                    style={{
                      color: '#64748b',
                      fontSize: 9,
                      fontWeight: 600,
                    }}
                  >
                    {severity}
                  </div>
                </button>
              )
            },
          )}
        </div>
      </div>


      <div
        style={{
          padding: '16px 18px',
          borderRadius: 10,
          background:
            'var(--bg-surface)',
          border:
            '1px solid var(--border)',
          marginBottom: 24,
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'repeat(4, minmax(0, 1fr))',
            gap: 14,
          }}
        >
          <div>
            <div
              style={{
                color: '#64748b',
                fontSize: 9,
                marginBottom: 4,
                textTransform:
                  'uppercase',
              }}
            >
              Correlated Groups
            </div>

            <div
              style={{
                color: '#e2e8f0',
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              {
                assessment.correlated_groups
              }
            </div>
          </div>


          <div>
            <div
              style={{
                color: '#64748b',
                fontSize: 9,
                marginBottom: 4,
                textTransform:
                  'uppercase',
              }}
            >
              Findings Merged
            </div>

            <div
              style={{
                color: '#e2e8f0',
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              {
                assessment
                  .duplicate_findings_merged
              }
            </div>
          </div>


          <div>
            <div
              style={{
                color: '#64748b',
                fontSize: 9,
                marginBottom: 4,
                textTransform:
                  'uppercase',
              }}
            >
              Dependency Files
            </div>

            <div
              style={{
                color: '#e2e8f0',
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              {
                assessment
                  .repository_profile
                  .dependency_files
                  .length
              }
            </div>
          </div>


          <div>
            <div
              style={{
                color: '#64748b',
                fontSize: 9,
                marginBottom: 4,
                textTransform:
                  'uppercase',
              }}
            >
              Configuration Files
            </div>

            <div
              style={{
                color: '#e2e8f0',
                fontSize: 13,
                fontWeight: 600,
              }}
            >
              {
                assessment
                  .repository_profile
                  .configuration_files
                  .length
              }
            </div>
          </div>
        </div>
      </div>


      <div
        style={{
          display: 'flex',
          justifyContent:
            'space-between',
          alignItems: 'center',
          marginBottom: 12,
        }}
      >
        <div>
          <h2
            style={{
              color: '#e2e8f0',
              fontSize: 15,
              fontWeight: 700,
              margin: '0 0 3px',
            }}
          >
            Security Findings
          </h2>

          <div
            style={{
              color: '#64748b',
              fontSize: 10,
            }}
          >
            Showing{' '}
            {filteredFindings.length}{' '}
            of{' '}
            {assessment.findings.length}{' '}
            consolidated findings
          </div>
        </div>


        {severityFilter !== 'ALL' && (
          <button
            type="button"
            onClick={() =>
              setSeverityFilter('ALL')
            }
            style={{
              background: 'none',
              border: 'none',
              color: '#7c3aed',
              cursor: 'pointer',
              fontSize: 11,
            }}
          >
            Clear severity filter
          </button>
        )}
      </div>


      {filteredFindings.length ===
      0 ? (
        <div
          style={{
            padding: 28,
            borderRadius: 10,
            background:
              'var(--bg-surface)',
            border:
              '1px solid var(--border)',
            textAlign: 'center',
            color: '#64748b',
            fontSize: 12,
          }}
        >
          No findings match the
          selected severity.
        </div>
      ) : (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
          }}
        >
          {filteredFindings.map(
            (finding) => (
              <button
                type="button"
                key={finding.id}
                onClick={() =>
                  onOpenFinding(
                    finding,
                  )
                }
                style={{
                  width: '100%',
                  padding:
                    '14px 16px',
                  borderRadius: 9,
                  background:
                    'var(--bg-surface)',
                  border:
                    '1px solid var(--border)',
                  cursor: 'pointer',
                  textAlign: 'left',
                  fontFamily:
                    'inherit',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems:
                      'flex-start',
                    gap: 14,
                  }}
                >
                  <SeverityBadge
                    severity={
                      finding.severity
                    }
                  />

                  <div
                    style={{
                      flex: 1,
                      minWidth: 0,
                    }}
                  >
                    <div
                      style={{
                        display:
                          'flex',
                        justifyContent:
                          'space-between',
                        gap: 16,
                        marginBottom: 5,
                      }}
                    >
                      <span
                        style={{
                          color:
                            '#e2e8f0',
                          fontSize: 12,
                          fontWeight:
                            600,
                        }}
                      >
                        {
                          finding.title
                        }
                      </span>

                      <span
                        style={{
                          color:
                            '#475569',
                          fontSize: 9,
                          flexShrink: 0,
                        }}
                      >
                        {
                          finding.scanner
                        }
                      </span>
                    </div>


                    <div
                      style={{
                        display:
                          'flex',
                        flexWrap:
                          'wrap',
                        gap: 7,
                        alignItems:
                          'center',
                      }}
                    >
                      <span
                        style={{
                          color:
                            '#7c3aed',
                          fontSize: 9,
                          fontWeight:
                            600,
                        }}
                      >
                        {
                          finding.category
                        }
                      </span>

                      <span
                        style={{
                          color:
                            '#334155',
                        }}
                      >
                        •
                      </span>

                      <span
                        style={{
                          color:
                            '#64748b',
                          fontSize: 9,
                          fontFamily:
                            'monospace',
                        }}
                      >
                        {finding.file ||
                          'Repository level'}

                        {finding.line
                          ? `:${finding.line}`
                          : ''}
                      </span>


                      {finding.cvss_score !==
                        null && (
                        <>
                          <span
                            style={{
                              color:
                                '#334155',
                            }}
                          >
                            •
                          </span>

                          <span
                            style={{
                              color:
                                '#94a3b8',
                              fontSize: 9,
                            }}
                          >
                            CVSS{' '}
                            {
                              finding.cvss_score
                            }
                          </span>
                        </>
                      )}


                      {finding.correlated && (
                        <>
                          <span
                            style={{
                              color:
                                '#334155',
                            }}
                          >
                            •
                          </span>

                          <span
                            style={{
                              color:
                                '#60a5fa',
                              fontSize: 9,
                            }}
                          >
                            Correlated ·{' '}
                            {
                              finding.evidence_count
                            }{' '}
                            evidence
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  <span
                    style={{
                      color: '#475569',
                      fontSize: 16,
                      paddingTop: 1,
                    }}
                  >
                    ›
                  </span>
                </div>
              </button>
            ),
          )}
        </div>
      )}


      <div
        style={{
          marginTop: 24,
          padding: '12px 14px',
          borderRadius: 8,
          border:
            '1px solid rgba(124,58,237,0.15)',
          background:
            'rgba(124,58,237,0.05)',
          color: '#64748b',
          fontSize: 10,
          lineHeight: 1.6,
        }}
      >
        Repository contents were
        processed temporarily for this
        assessment and are not retained
        by Ligtask. Historical results
        contain assessment metadata and
        security findings only.
      </div>
    </div>
  )
}