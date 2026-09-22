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


type MechanismStatus = {
  status: string
  scanner: string
  findings_count: number
  error: string | null
}


type AssessmentWithMechanisms =
  AssessmentDetail & {
    mechanism_statuses?: Record<
      string,
      MechanismStatus
    >
  }


const mechanismLabels: Record<
  string,
  string
> = {
  sast: 'SAST',
  dependency: 'Dependency',
  secret: 'Secret Detection',
  configuration: 'Configuration',
}


function mechanismStatusLabel(
  status: string,
) {
  switch (status) {
    case 'completed':
      return 'Completed'

    case 'timed_out':
      return 'Timed out'

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


function mechanismStatusColor(
  status: string,
) {
  switch (status) {
    case 'completed':
      return '#22c55e'

    case 'timed_out':
      return '#f59e0b'

    case 'failed':
      return '#ef4444'

    default:
      return '#94a3b8'
  }
}


const LANGUAGE_COLORS: Record<string, string> = {
  JavaScript: '#f7df1e',
  TypeScript: '#3178c6',
  Python: '#3572a5',
  PHP: '#4f5d95',
  HTML: '#e34c26',
  CSS: '#563d7c',
  JSON: '#cbcb41',
  YAML: '#cb171e',
  Markdown: '#083fa1',
  Shell: '#89e051',
  Dockerfile: '#384d54',
}


function getLanguageColor(language: string): string {
  return LANGUAGE_COLORS[language] ?? '#8b5cf6'
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

  const [reloadAttempt, setReloadAttempt] =
    useState(0)


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
  }, [assessmentId, reloadAttempt])


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
          â† Back to Scan History
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

          <div
            style={{
              marginTop: 14,
              display: 'flex',
              gap: 8,
            }}
          >
            <button
              type="button"
              onClick={() =>
                setReloadAttempt(
                  (n) => n + 1,
                )
              }
              style={{
                display:
                  'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '8px 14px',
                borderRadius: 7,
                border: 'none',
                background:
                  'var(--accent-purple)',
                color: '#ffffff',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Retry
            </button>

            <button
              type="button"
              onClick={() =>
                navigate('history')
              }
              style={{
                display:
                  'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '8px 14px',
                borderRadius: 7,
                border:
                  '1px solid var(--border)',
                background:
                  'transparent',
                color: '#94a3b8',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              â† Back to History
            </button>
          </div>
        </div>
      </div>
    )
  }


  const [searchQuery, setSearchQuery] =
    useState('')


  const severityFilteredFindings =
    severityFilter === 'ALL'
      ? assessment.findings
      : assessment.findings.filter(
          (finding) =>
            finding.severity ===
            severityFilter,
        )

  const normalizedQuery =
    searchQuery.trim().toLowerCase()

  const searchMatches = (
    finding: AssessmentFinding,
  ) => {
    if (normalizedQuery === '') {
      return true
    }

    const haystacks = [
      finding.title,
      finding.rule_id,
      finding.package_name,
      finding.package_version,
      finding.cve_id,
      finding.file_path,
      finding.recommendation,
      finding.detail,
      finding.recommended_action,
    ]

    return haystacks.some(
      (field) =>
        typeof field === 'string' &&
        field.toLowerCase().includes(
          normalizedQuery,
        ),
    )
  }

  const filteredFindings =
    severityFilteredFindings.filter(
      searchMatches,
    )


  const totalFindings =
    assessment.consolidated_findings_count

  const assessmentWithMechanisms =
    assessment as AssessmentWithMechanisms

  const mechanismStatuses =
    assessmentWithMechanisms
      .mechanism_statuses ?? {}

  const mechanismEntries = [
    'sast',
    'dependency',
    'secret',
    'configuration',
  ]
    .map((key) => ({
      key,
      mechanism:
        mechanismStatuses[key],
    }))
    .filter(
      (
        entry,
      ): entry is {
        key: string
        mechanism: MechanismStatus
      } => Boolean(entry.mechanism),
    )

  const repoProfile = assessment.repository_profile ?? {
    total_files: assessment.total_files,
    languages: {},
    dependency_files: [],
    configuration_files: [],
  }

  const languageEntries = Object.entries(
    repoProfile.languages ?? {},
  ).sort(([, a], [, b]) => b - a)

  const totalLanguageFiles = languageEntries.reduce(
    (sum, [, c]) => sum + c,
    0,
  )

  const rawCount = assessment.raw_findings_count
  const consolidatedCount =
    assessment.consolidated_findings_count

  const reductionRatio =
    rawCount > 0
      ? Math.max(
          0,
          Math.round(
            ((rawCount - consolidatedCount) / rawCount) * 100,
          ),
        )
      : 0

  const totalMechanismFindings = mechanismEntries.reduce(
    (sum, { mechanism }) => sum + mechanism.findings_count,
    0,
  )


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
        â† Back to Scan History
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
              â€¢
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
              â€¢
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


      {assessment.status ===
        'partial' && (
        <div
          style={{
            marginBottom: 20,
            padding: '16px 18px',
            borderRadius: 10,
            border:
              '1px solid rgba(245,158,11,0.35)',
            background:
              'rgba(245,158,11,0.08)',
          }}
        >
          <div
            style={{
              color: '#f59e0b',
              fontSize: 13,
              fontWeight: 700,
              marginBottom: 6,
            }}
          >
            Partial Assessment
          </div>

          <div
            style={{
              color: '#cbd5e1',
              fontSize: 11,
              lineHeight: 1.6,
            }}
          >
            One or more security analysis
            mechanisms did not complete.
            Findings from mechanisms that
            completed remain valid, but these
            results do not represent a complete
            repository assessment.
          </div>
        </div>
      )}


      {mechanismEntries.length > 0 && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'repeat(4, minmax(0, 1fr))',
            gap: 10,
            marginBottom: 24,
          }}
        >
          {mechanismEntries.map(
            ({ key, mechanism }) => {
              const statusColor =
                mechanismStatusColor(
                  mechanism.status,
                )

              return (
                <div
                  key={key}
                  className="interactive-card"
                  style={{
                    padding: '13px 14px',
                    borderRadius: 9,
                    background:
                      'var(--bg-surface)',
                    border:
                      `1px solid ${statusColor}35`,
                    minWidth: 0,
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent:
                        'space-between',
                      gap: 8,
                      alignItems: 'center',
                      marginBottom: 7,
                    }}
                  >
                    <span
                      style={{
                        color: '#cbd5e1',
                        fontSize: 10,
                        fontWeight: 700,
                      }}
                    >
                      {mechanismLabels[key] ??
                        key}
                    </span>

                    <span
                      style={{
                        color: statusColor,
                        fontSize: 9,
                        fontWeight: 700,
                      }}
                    >
                      {mechanismStatusLabel(
                        mechanism.status,
                      )}
                    </span>
                  </div>

                  <div
                    style={{
                      color: '#64748b',
                      fontSize: 9,
                      lineHeight: 1.5,
                    }}
                  >
                    {mechanism.scanner}
                    {' Â· '}
                    {mechanism.findings_count}{' '}
                    findings
                  </div>

                  {mechanism.error && (
                    <div
                      style={{
                        marginTop: 7,
                        color: '#fbbf24',
                        fontSize: 9,
                        lineHeight: 1.45,
                        overflowWrap:
                          'anywhere',
                      }}
                    >
                      {mechanism.error}
                    </div>
                  )}
                </div>
              )
            },
          )}
        </div>
      )}


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
            className="interactive-card"
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
            display: 'flex',
            justifyContent:
              'space-between',
            alignItems: 'center',
            marginBottom: 14,
          }}
        >
          <div
            style={{
              color: '#94a3b8',
              fontSize: 11,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}
          >
            Severity Distribution
          </div>

          {totalFindings > 0 && (
            <div
              style={{
                color: '#64748b',
                fontSize: 11,
              }}
            >
              {totalFindings} consolidated finding{totalFindings === 1 ? '' : 's'}
            </div>
          )}
        </div>

        <div
          style={{
            height: 8,
            width: '100%',
            borderRadius: 999,
            overflow: 'hidden',
            display: 'flex',
            background:
              'var(--bg-surface-2)',
            marginBottom: 16,
          }}
        >
          {totalFindings === 0 ? (
            <div
              style={{
                width: '100%',
                background:
                  'rgba(34, 197, 94, 0.25)',
              }}
            />
          ) : (
            severityOrder.map((sev) => {
              const count =
                assessment
                  .severity_summary[
                  sev
                ] || 0
              if (count === 0)
                return null
              const pct =
                (count /
                  totalFindings) *
                100
              const isSelected =
                severityFilter ===
                  'ALL' ||
                severityFilter ===
                  sev
              return (
                <div
                  key={sev}
                  title={`${sev}: ${count} (${pct.toFixed(1)}%)`}
                  onClick={() =>
                    setSeverityFilter(
                      severityFilter ===
                        sev
                        ? 'ALL'
                        : sev,
                    )
                  }
                  style={{
                    width: `${pct}%`,
                    backgroundColor:
                      severityColor(
                        sev,
                      ),
                    cursor:
                      'pointer',
                    transition:
                      'opacity 0.2s ease',
                    opacity:
                      isSelected
                        ? 1
                        : 0.25,
                  }}
                />
              )
            })
          )}
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
                ] || 0
              const isSelected =
                severityFilter ===
                severity
              const pct =
                totalFindings > 0
                  ? (
                      (count /
                        totalFindings) *
                      100
                    ).toFixed(0)
                  : '0'

              return (
                <button
                  type="button"
                  key={severity}
                  className="interactive-card"
                  onClick={() =>
                    setSeverityFilter(
                      isSelected
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
                      isSelected
                        ? `${severityColor(
                            severity,
                          )}15`
                        : 'var(--bg-surface-2)',
                    border:
                      isSelected
                        ? `1px solid ${severityColor(
                            severity,
                          )}66`
                        : '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems:
                        'baseline',
                      justifyContent:
                        'space-between',
                      marginBottom: 3,
                    }}
                  >
                    <span
                      style={{
                        color:
                          severityColor(
                            severity,
                          ),
                        fontSize: 18,
                        fontWeight: 700,
                      }}
                    >
                      {count}
                    </span>

                    {totalFindings >
                      0 &&
                      count > 0 && (
                        <span
                          style={{
                            color:
                              '#64748b',
                            fontSize: 10,
                            fontWeight: 600,
                          }}
                        >
                          {pct}%
                        </span>
                      )}
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
          display: 'grid',
          gridTemplateColumns:
            'repeat(2, minmax(0, 1fr))',
          gap: 16,
          marginBottom: 24,
        }}
      >
        <div
          className="interactive-card"
          style={{
            padding: '18px 20px',
            borderRadius: 10,
            background:
              'var(--bg-surface)',
            border:
              '1px solid var(--border)',
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent:
                'space-between',
              alignItems: 'center',
            }}
          >
            <div
              style={{
                color: '#94a3b8',
                fontSize: 11,
                fontWeight: 600,
                textTransform:
                  'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              Repository Profile & Languages
            </div>

            <span
              style={{
                color: '#64748b',
                fontSize: 10,
                fontWeight: 500,
              }}
            >
              {assessment.total_files} files analyzed
            </span>
          </div>

          {languageEntries.length > 0 ? (
            <div>
              <div
                style={{
                  height: 8,
                  width: '100%',
                  borderRadius: 999,
                  overflow: 'hidden',
                  display: 'flex',
                  background:
                    'var(--bg-surface-2)',
                  marginBottom: 10,
                }}
              >
                {languageEntries.map(
                  ([lang, count]) => {
                    const pct =
                      (count /
                        totalLanguageFiles) *
                      100
                    return (
                      <div
                        key={lang}
                        title={`${lang}: ${count} files (${pct.toFixed(1)}%)`}
                        style={{
                          width: `${pct}%`,
                          backgroundColor:
                            getLanguageColor(
                              lang,
                            ),
                        }}
                      />
                    )
                  },
                )}
              </div>

              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 10,
                }}
              >
                {languageEntries.map(
                  ([lang, count]) => {
                    const pct = (
                      (count /
                        totalLanguageFiles) *
                      100
                    ).toFixed(1)
                    const color =
                      getLanguageColor(
                        lang,
                      )
                    return (
                      <div
                        key={lang}
                        style={{
                          display:
                            'flex',
                          alignItems:
                            'center',
                          gap: 5,
                          fontSize: 10,
                          color: '#cbd5e1',
                        }}
                      >
                        <span
                          style={{
                            width: 7,
                            height: 7,
                            borderRadius:
                              '50%',
                            backgroundColor:
                              color,
                            display:
                              'inline-block',
                          }}
                        />
                        <span
                          style={{
                            fontWeight: 600,
                          }}
                        >
                          {lang}
                        </span>
                        <span
                          style={{
                            color: '#64748b',
                          }}
                        >
                          {pct}% ({count})
                        </span>
                      </div>
                    )
                  },
                )}
              </div>
            </div>
          ) : (
            <div
              style={{
                color: '#64748b',
                fontSize: 11,
              }}
            >
              No recognized language files detected.
            </div>
          )}

          <div
            style={{
              display: 'grid',
              gridTemplateColumns:
                'repeat(2, minmax(0, 1fr))',
              gap: 12,
              paddingTop: 12,
              borderTop:
                '1px solid var(--bg-surface-3)',
            }}
          >
            <div>
              <div
                style={{
                  color: '#64748b',
                  fontSize: 9,
                  fontWeight: 600,
                  textTransform:
                    'uppercase',
                  letterSpacing: '0.04em',
                  marginBottom: 6,
                }}
              >
                Dependency Manifests (
                {
                  repoProfile
                    .dependency_files
                    .length
                }
                )
              </div>

              {repoProfile
                .dependency_files.length >
              0 ? (
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 5,
                  }}
                >
                  {repoProfile.dependency_files.map(
                    (file) => (
                      <span
                        key={file}
                        style={{
                          display:
                            'inline-block',
                          padding:
                            '2px 7px',
                          borderRadius: 4,
                          background:
                            'rgba(59, 130, 246, 0.1)',
                          border:
                            '1px solid rgba(59, 130, 246, 0.25)',
                          color: '#93c5fd',
                          fontSize: 9,
                          fontFamily:
                            'monospace',
                        }}
                      >
                        {file}
                      </span>
                    ),
                  )}
                </div>
              ) : (
                <span
                  style={{
                    color: '#64748b',
                    fontSize: 10,
                  }}
                >
                  None detected
                </span>
              )}
            </div>

            <div>
              <div
                style={{
                  color: '#64748b',
                  fontSize: 9,
                  fontWeight: 600,
                  textTransform:
                    'uppercase',
                  letterSpacing: '0.04em',
                  marginBottom: 6,
                }}
              >
                Configuration Files (
                {
                  repoProfile
                    .configuration_files
                    .length
                }
                )
              </div>

              {repoProfile
                .configuration_files
                .length > 0 ? (
                <div
                  style={{
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: 5,
                  }}
                >
                  {repoProfile.configuration_files.map(
                    (file) => (
                      <span
                        key={file}
                        style={{
                          display:
                            'inline-block',
                          padding:
                            '2px 7px',
                          borderRadius: 4,
                          background:
                            'rgba(168, 85, 247, 0.1)',
                          border:
                            '1px solid rgba(168, 85, 247, 0.25)',
                          color: '#d8b4fe',
                          fontSize: 9,
                          fontFamily:
                            'monospace',
                        }}
                      >
                        {file}
                      </span>
                    ),
                  )}
                </div>
              ) : (
                <span
                  style={{
                    color: '#64748b',
                    fontSize: 10,
                  }}
                >
                  None detected
                </span>
              )}
            </div>
          </div>
        </div>


        <div
          className="interactive-card"
          style={{
            padding: '18px 20px',
            borderRadius: 10,
            background:
              'var(--bg-surface)',
            border:
              '1px solid var(--border)',
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent:
                'space-between',
              alignItems: 'center',
            }}
          >
            <div
              style={{
                color: '#94a3b8',
                fontSize: 11,
                fontWeight: 600,
                textTransform:
                  'uppercase',
                letterSpacing: '0.05em',
              }}
            >
              Consolidation Pipeline
            </div>

            {rawCount > 0 &&
              reductionRatio > 0 && (
                <span
                  style={{
                    color: '#34d399',
                    background:
                      'rgba(52, 211, 153, 0.1)',
                    border:
                      '1px solid rgba(52, 211, 153, 0.25)',
                    padding: '2px 8px',
                    borderRadius: 12,
                    fontSize: 9,
                    fontWeight: 700,
                  }}
                >
                  {reductionRatio}% Noise Reduced
                </span>
              )}
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent:
                'space-between',
              gap: 8,
              padding: '10px 12px',
              borderRadius: 8,
              background:
                'var(--bg-surface-2)',
              border:
                '1px solid var(--border)',
            }}
          >
            <div
              style={{
                textAlign: 'center',
                flex: 1,
              }}
            >
              <div
                style={{
                  color: '#94a3b8',
                  fontSize: 9,
                  textTransform:
                    'uppercase',
                  marginBottom: 2,
                }}
              >
                Raw Detections
              </div>

              <div
                style={{
                  color: '#e2e8f0',
                  fontSize: 16,
                  fontWeight: 700,
                }}
              >
                {rawCount}
              </div>
            </div>

            <span
              style={{
                color: '#64748b',
                fontSize: 14,
              }}
            >
              â†’
            </span>

            <div
              style={{
                textAlign: 'center',
                flex: 1.4,
              }}
            >
              <div
                style={{
                  color: '#a78bfa',
                  fontSize: 9,
                  textTransform:
                    'uppercase',
                  marginBottom: 2,
                }}
              >
                Correlation Engine
              </div>

              <div
                style={{
                  color: '#cbd5e1',
                  fontSize: 10,
                  fontWeight: 600,
                }}
              >
                {
                  assessment
                    .duplicate_findings_merged
                }{' '}
                merged Â·{' '}
                {
                  assessment
                    .correlated_groups
                }{' '}
                correlated
              </div>
            </div>

            <span
              style={{
                color: '#64748b',
                fontSize: 14,
              }}
            >
              â†’
            </span>

            <div
              style={{
                textAlign: 'center',
                flex: 1,
              }}
            >
              <div
                style={{
                  color: '#38bdf8',
                  fontSize: 9,
                  textTransform:
                    'uppercase',
                  marginBottom: 2,
                }}
              >
                Consolidated
              </div>

              <div
                style={{
                  color: '#38bdf8',
                  fontSize: 16,
                  fontWeight: 700,
                }}
              >
                {consolidatedCount}
              </div>
            </div>
          </div>

          <div>
            <div
              style={{
                color: '#64748b',
                fontSize: 9,
                fontWeight: 600,
                textTransform:
                  'uppercase',
                letterSpacing: '0.04em',
                marginBottom: 8,
              }}
            >
              Mechanism Findings Breakdown
            </div>

            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 7,
              }}
            >
              {mechanismEntries.map(
                ({ key, mechanism }) => {
                  const contribPct =
                    totalMechanismFindings >
                    0
                      ? (mechanism.findings_count /
                          totalMechanismFindings) *
                        100
                      : 0

                  const barColor =
                    key === 'sast'
                      ? '#7c3aed'
                      : key === 'dependency'
                        ? '#3b82f6'
                        : key === 'secret'
                          ? '#f59e0b'
                          : '#10b981'

                  return (
                    <div
                      key={key}
                      style={{
                        display: 'flex',
                        alignItems:
                          'center',
                        gap: 8,
                        fontSize: 10,
                      }}
                    >
                      <span
                        style={{
                          width: 84,
                          color: '#cbd5e1',
                          fontWeight: 600,
                          flexShrink: 0,
                        }}
                      >
                        {mechanismLabels[
                          key
                        ] ?? key}
                      </span>

                      <div
                        style={{
                          flex: 1,
                          height: 6,
                          borderRadius: 3,
                          background:
                            'var(--bg-surface-3)',
                          overflow:
                            'hidden',
                        }}
                      >
                        <div
                          style={{
                            height: '100%',
                            width: `${contribPct}%`,
                            background:
                              barColor,
                            borderRadius: 3,
                            transition:
                              'width 0.3s ease',
                          }}
                        />
                      </div>

                      <span
                        style={{
                          width: 64,
                          textAlign:
                            'right',
                          color: '#94a3b8',
                          fontFamily:
                            'monospace',
                          fontSize: 10,
                          flexShrink: 0,
                        }}
                      >
                        {
                          mechanism.findings_count
                        }{' '}
                        (
                        {contribPct.toFixed(
                          0,
                        )}
                        %)
                      </span>
                    </div>
                  )
                },
              )}
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


        {assessment.findings.length >
          0 && (
          <input
            type="search"
            value={searchQuery}
            onChange={(event) =>
              setSearchQuery(
                event.target.value,
              )
            }
            placeholder="Search findingsâ€¦"
            aria-label="Search findings"
            style={{
              flex: '0 1 260px',
              maxWidth: 260,
              padding:
                '9px 12px 9px 34px',
              borderRadius: 10,
              border:
                '1px solid var(--border)',
              background:
                'var(--bg-surface)',
              color:
                'var(--text-primary)',
              fontSize: 12,
              outline: 'none',
              backgroundImage:
                "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cline x1='21' y1='21' x2='16.5' y2='16.5'/%3E%3C/svg%3E\")",
              backgroundRepeat: 'no-repeat',
              backgroundPosition:
                '12px center',
            }}
          />
        )}


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
                className="interactive-card"
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
                        â€¢
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
                            â€¢
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
                            â€¢
                          </span>

                          <span
                            style={{
                              color:
                                '#60a5fa',
                              fontSize: 9,
                            }}
                          >
                            Correlated Â·{' '}
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
                    â€º
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
        by TALGED. Historical results
        contain assessment metadata and
        security findings only.
      </div>
    </div>
  )
}
