import {
  useLayoutEffect,
  useRef,
} from 'react'

import type {
  AssessmentFinding,
  FindingSeverity,
} from '../types/assessment'
import { findingReview } from '../services/findingExplanation'


interface FindingDetailScreenProps {
  finding: AssessmentFinding
  onBack: () => void
}


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


function DetailItem({
  label,
  value,
  mono = false,
}: {
  label: string
  value:
    | string
    | number
    | null
    | undefined
  mono?: boolean
}) {
  if (
    value === null ||
    value === undefined ||
    value === ''
  ) {
    return null
  }

  return (
    <div>
      <div
        style={{
          color: '#64748b',
          fontSize: 9,
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          marginBottom: 5,
        }}
      >
        {label}
      </div>

      <div
        style={{
          color: '#cbd5e1',
          fontSize: 11,
          lineHeight: 1.6,
          overflowWrap: 'anywhere',
          fontFamily: mono
            ? 'JetBrains Mono, monospace'
            : 'inherit',
        }}
      >
        {value}
      </div>
    </div>
  )
}


function Section({
  title,
  children,
}: {
  title: string
  children: React.ReactNode
}) {
  return (
    <section
      style={{
        padding: 20,
        borderRadius: 10,
        border:
          '1px solid var(--border)',
        background:
          'var(--bg-surface)',
      }}
    >
      <h2
        style={{
          margin: '0 0 14px',
          color: '#e2e8f0',
          fontSize: 13,
          fontWeight: 700,
        }}
      >
        {title}
      </h2>

      {children}
    </section>
  )
}


export default function FindingDetailScreen({
  finding,
  onBack,
}: FindingDetailScreenProps) {
  const pageRef =
    useRef<HTMLDivElement | null>(null)

  const color =
    severityColor(finding.severity)


  /*
   * Always open a finding at the top.
   *
   * This resets both possible scroll
   * containers:
   *
   * 1. Browser/document scroll
   * 2. Finding detail page scroll
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
  }, [finding.id])


  const location =
    finding.file && finding.line
      ? `${finding.file}:${finding.line}`
      : finding.file ||
        'Repository level'


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
        onClick={onBack}
        style={{
          background: 'none',
          border: 'none',
          padding: 0,
          marginBottom: 22,
          color: '#7c3aed',
          cursor: 'pointer',
          fontSize: 12,
          fontWeight: 500,
        }}
      >
        ← Back to Assessment Results
      </button>


      <div
        style={{
          marginBottom: 24,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 10,
            marginBottom: 12,
          }}
        >
          <span
            style={{
              padding: '5px 9px',
              borderRadius: 5,
              color,
              background: `${color}18`,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: '0.04em',
            }}
          >
            {finding.severity}
          </span>

          <span
            style={{
              color: '#7c3aed',
              fontSize: 10,
              fontWeight: 600,
            }}
          >
            {finding.category}
          </span>

          <span
            style={{
              color: '#475569',
              fontSize: 10,
            }}
          >
            {finding.scanner}
          </span>
        </div>


        <h1
          style={{
            margin: '0 0 10px',
            color: '#e2e8f0',
            fontSize: 22,
            lineHeight: 1.35,
            fontWeight: 700,
          }}
        >
          {finding.title}
        </h1>


        <div
          style={{
            color: '#64748b',
            fontFamily:
              'JetBrains Mono, monospace',
            fontSize: 10,
            overflowWrap: 'anywhere',
          }}
        >
          {location}
        </div>
      </div>


      <div
        style={{
          display: 'grid',
          gridTemplateColumns:
            'repeat(4, minmax(0, 1fr))',
          gap: 12,
          marginBottom: 20,
        }}
      >
        <div
          style={{
            padding: '15px 17px',
            borderRadius: 9,
            border:
              '1px solid var(--border)',
            background:
              'var(--bg-surface)',
          }}
        >
          <DetailItem
            label="Severity"
            value={finding.severity}
          />
        </div>


        <div
          style={{
            padding: '15px 17px',
            borderRadius: 9,
            border:
              '1px solid var(--border)',
            background:
              'var(--bg-surface)',
          }}
        >
          <DetailItem
            label="CVSS Score"
            value={
              finding.cvss_score !== null
                ? finding.cvss_score
                : 'Not provided'
            }
          />
        </div>


        <div
          style={{
            padding: '15px 17px',
            borderRadius: 9,
            border:
              '1px solid var(--border)',
            background:
              'var(--bg-surface)',
          }}
        >
          <DetailItem
            label="Scanner"
            value={finding.scanner}
          />
        </div>


        <div
          style={{
            padding: '15px 17px',
            borderRadius: 9,
            border:
              '1px solid var(--border)',
            background:
              'var(--bg-surface)',
          }}
        >
          <DetailItem
            label="Category"
            value={finding.category}
          />
        </div>
      </div>


      <div
        style={{
          display: 'grid',
          gridTemplateColumns:
            '2fr 1fr',
          gap: 16,
          alignItems: 'start',
        }}
      >
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          }}
        >
          <Section title="Finding Description">
            <p style={{ color: 'var(--text-secondary, #64748b)', fontSize: 12, lineHeight: 1.7 }}>
              {findingReview(finding)}
            </p>
            <p
              style={{
                margin: 0,
                color: '#94a3b8',
                fontSize: 12,
                lineHeight: 1.75,
              }}
            >
              {finding.description ||
                finding.message ||
                'No additional description was provided.'}
            </p>
          </Section>


          <Section title="Recommended Remediation">
            <p
              style={{
                margin: 0,
                color: '#cbd5e1',
                fontSize: 12,
                lineHeight: 1.75,
              }}
            >
              {finding.recommendation ||
                'Review the identified security issue and apply an appropriate secure implementation.'}
            </p>

            {finding.recommended_action && (
              <div
                style={{
                  marginTop: 12,
                  padding: '10px 14px',
                  borderRadius: 8,
                  background:
                    'rgba(34, 197, 94, 0.08)',
                  border:
                    '1px solid rgba(34, 197, 94, 0.2)',
                }}
              >
                <div
                  style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: '#4ade80',
                    margin: '0 0 4px',
                    textTransform: 'uppercase',
                    letterSpacing: '0.05em',
                  }}
                >
                  Recommended Action
                </div>

                <div
                  style={{
                    margin: 0,
                    color: '#e2e8f0',
                    fontSize: 13,
                    fontWeight: 500,
                    lineHeight: 1.6,
                  }}
                >
                  {finding.recommended_action}
                </div>
              </div>
            )}


            {finding.guidance_source && (
              <div
                style={{
                  marginTop: 14,
                  paddingTop: 12,
                  borderTop:
                    '1px solid var(--border)',
                  color: '#64748b',
                  fontSize: 9,
                }}
              >
                Guidance source:{' '}

                <span
                  style={{
                    color: '#94a3b8',
                  }}
                >
                  {
                    finding.guidance_source
                  }
                </span>
              </div>
            )}
          </Section>


          {finding.message &&
            finding.message !==
              finding.description && (
              <Section title="Scanner Message">
                <p
                  style={{
                    margin: 0,
                    color: '#94a3b8',
                    fontSize: 11,
                    lineHeight: 1.7,
                  }}
                >
                  {finding.message}
                </p>
              </Section>
            )}
        </div>


        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          }}
        >
          <Section title="Finding Information">
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 16,
              }}
            >
              <DetailItem
                label="Rule ID"
                value={finding.rule_id}
                mono
              />

              <DetailItem
                label="File"
                value={
                  finding.file ||
                  'Repository level'
                }
                mono
              />

              <DetailItem
                label="Line"
                value={finding.line}
              />

              <DetailItem
                label="Package"
                value={finding.package}
                mono
              />

              <DetailItem
                label="Version"
                value={finding.version}
                mono
              />

              <DetailItem
                label="Ecosystem"
                value={finding.ecosystem}
              />
            </div>
          </Section>


          {(finding.cvss_vector ||
            finding.cvss_version ||
            finding.cvss_score !== null) && (
            <Section title="CVSS Information">
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 16,
                }}
              >
                <DetailItem
                  label="Score"
                  value={
                    finding.cvss_score
                  }
                />

                <DetailItem
                  label="Version"
                  value={
                    finding.cvss_version
                  }
                />

                <DetailItem
                  label="Vector"
                  value={
                    finding.cvss_vector
                  }
                  mono
                />
              </div>
            </Section>
          )}


          <Section title="Correlation & Provenance">
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 16,
              }}
            >
              <DetailItem
                label="Correlated"
                value={
                  finding.correlated
                    ? 'Yes'
                    : 'No'
                }
              />

              <DetailItem
                label={finding.category === 'DEPENDENCY' ? 'Occurrences in scanned lockfile' : 'Evidence Count'}
                value={
                  finding.evidence_count
                }
              />

              <DetailItem
                label="Sources"
                value={
                  finding.sources.length
                    ? finding.sources.join(
                        ', ',
                      )
                    : finding.scanner
                }
              />

              <DetailItem
                label="Source Rule IDs"
                value={
                  finding
                    .source_rule_ids
                    .length
                    ? finding.source_rule_ids.join(
                        ', ',
                      )
                    : finding.rule_id
                }
                mono
              />
            </div>
          </Section>
        </div>
      </div>


      <div
        style={{
          marginTop: 20,
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
        TALGED does not retain repository
        source code after assessment. This
        historical view displays persisted
        assessment metadata and security
        finding information only.
      </div>
    </div>
  )
}
