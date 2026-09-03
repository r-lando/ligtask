import HistoryScreen from './pages/HistoryScreen'
import AssessmentResultsScreen from './pages/AssessmentResultsScreen'
import { useState, useEffect, useRef } from 'react'
import Sidebar, { type Screen } from './components/Sidebar'
import type { AssessmentFinding } from './types/assessment'
import RealFindingDetailScreen from './pages/FindingDetailScreen'
import {
  assessGitHubRepository,
  uploadRepository,
} from './services/api'

type AssessmentInput =
  | {
      type: 'GITHUB'
      repositoryUrl: string
    }
  | {
      type: 'ZIP'
      file: File
    }
// ─── Shared Components ────────────────────────────────────────────────────────

interface ButtonProps {
  children: React.ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  style?: React.CSSProperties
  disabled?: boolean
}

function Button({ children, onClick, variant = 'primary', size = 'md', style: extraStyle, disabled }: ButtonProps) {
  const [hover, setHover] = useState(false)

  const base: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 8,
    border: 'none', cursor: disabled ? 'not-allowed' : 'pointer',
    fontFamily: 'inherit', fontWeight: 600,
    borderRadius: size === 'lg' ? 12 : 8,
    transition: 'all 0.15s',
    opacity: disabled ? 0.5 : 1,
    padding: size === 'lg' ? '14px 28px' : size === 'sm' ? '6px 12px' : '10px 18px',
    fontSize: size === 'lg' ? 15 : size === 'sm' ? 12 : 13,
  }

  const variants: Record<string, React.CSSProperties> = {
    primary: {
      background: hover ? '#6d28d9' : 'linear-gradient(135deg, #7c3aed, #6d28d9)',
      color: '#fff',
      boxShadow: hover ? '0 0 20px rgba(124,58,237,0.4)' : '0 0 12px rgba(124,58,237,0.2)',
    },
    secondary: {
      background: hover ? 'var(--bg-surface-3)' : 'var(--bg-surface-2)',
      color: '#e2e8f0',
      border: '1px solid var(--border-strong)',
    },
    ghost: {
      background: 'transparent',
      color: hover ? '#a78bfa' : '#64748b',
    },
  }

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{ ...base, ...variants[variant], ...extraStyle }}
    >
      {children}
    </button>
  )
}

function Card({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 14,
      ...style,
    }}>
      {children}
    </div>
  )
}


function CheckIcon({ checked = true }: { checked?: boolean }) {
  return (
    <div style={{
      width: 18, height: 18, borderRadius: '50%',
      background: checked ? 'rgba(34,197,94,0.15)' : 'var(--bg-surface-3)',
      border: checked ? '1px solid rgba(34,197,94,0.3)' : '1px solid var(--border)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      flexShrink: 0,
    }}>
      {checked && (
        <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
          <path d="M2 5L4 7L8 3" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )}
    </div>
  )
}

// ─── Screen 1: Home ──────────────────────────────────────────────────────────

function HomeScreen({ navigate }: { navigate: (s: Screen) => void }) {
  const features = [
    {
      icon: (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#7c3aed" strokeWidth="1.5">
          <rect x="2" y="3" width="16" height="14" rx="2" />
          <path d="M7 7h6M7 10h4M7 13h2" strokeLinecap="round" />
        </svg>
      ),
      color: '#7c3aed',
      title: 'Repository-Aware',
      desc: 'Analyzes source code, dependencies, files, and configuration files for comprehensive security coverage.',
    },
    {
      icon: (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#22c55e" strokeWidth="1.5">
          <path d="M10 2L17 5.5V10C17 14.1 13.8 17.8 10 19C6.2 17.8 3 14.1 3 10V5.5L10 2Z" />
          <path d="M7 10L9 12L13 8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ),
      color: '#22c55e',
      title: 'Privacy-Preserving',
      desc: 'Repository contents are processed temporarily and automatically deleted after assessment. Source code is not permanently stored.',
    },
    {
      icon: (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#f97316" strokeWidth="1.5">
          <path d="M10 2l2.5 5.5L18 8.5l-4 4L15 18l-5-2.5L5 18l1-5.5-4-4 5.5-.5L10 2z" />
        </svg>
      ),
      color: '#f97316',
      title: 'Actionable Insights',
      desc: 'Get clear vulnerability reports with severity levels and recommended mitigations.',
    },
  ]

  return (
    <div style={{ display: 'flex', flex: 1, minHeight: '100vh' }}>
      <div style={{ flex: 1, padding: '48px 56px', display: 'flex', flexDirection: 'column', justifyContent: 'center', maxWidth: 560 }}>
        <h1 style={{
          fontSize: 42, fontWeight: 800, lineHeight: 1.15,
          color: '#e2e8f0', margin: '0 0 8px',
          letterSpacing: '-0.03em',
        }}>
          Secure Your Code.<br />Protect Your Projects.
        </h1>
        <h2 style={{
          fontSize: 28, fontWeight: 700, margin: '0 0 24px',
          background: 'linear-gradient(90deg, #7c3aed, #3b82f6)',
          WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        }}>
          Ligtask
        </h2>
        <p style={{ fontSize: 14, color: '#64748b', lineHeight: 1.7, margin: '0 0 40px', maxWidth: 420 }}>
          Ligtask is a privacy-preserving, repository-aware security assessment platform that uses rule-based static code analysis to identify potential vulnerabilities in your web application repositories.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 48 }}>
          {features.map((f) => (
            <div key={f.title} style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
              <div style={{
                width: 40, height: 40, borderRadius: 10, flexShrink: 0,
                background: `rgba(${f.color === '#7c3aed' ? '124,58,237' : f.color === '#22c55e' ? '34,197,94' : '249,115,22'},0.1)`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                {f.icon}
              </div>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', marginBottom: 4 }}>{f.title}</div>
                <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.6 }}>{f.desc}</div>
              </div>
            </div>
          ))}
        </div>

        <Button size="lg" onClick={() => navigate('repo')} style={{ alignSelf: 'flex-start' }}>
          Start New Assessment
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M3 8h10M9 4l4 4-4 4" />
          </svg>
        </Button>

        <p style={{ marginTop: 16, fontSize: 12, color: '#334155' }}>
          Begin by submitting your repository for assessment.
        </p>
      </div>

      <div style={{
        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        position: 'relative', overflow: 'hidden',
      }}>
        <div style={{
          position: 'absolute', inset: 0,
          background: 'radial-gradient(ellipse at 60% 50%, rgba(124,58,237,0.12) 0%, transparent 70%)',
        }} />
        <div style={{
          width: 280, height: 280,
          background: 'linear-gradient(135deg, rgba(124,58,237,0.2), rgba(59,130,246,0.15))',
          borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '1px solid rgba(124,58,237,0.2)',
          boxShadow: '0 0 80px rgba(124,58,237,0.15)',
        }}>
          <div style={{
            width: 180, height: 180,
            background: 'linear-gradient(135deg, rgba(124,58,237,0.3), rgba(59,130,246,0.2))',
            borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: '1px solid rgba(124,58,237,0.3)',
          }}>
            <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
              <path d="M40 5L70 20V38C70 56 57 70 40 76C23 70 10 56 10 38V20L40 5Z"
                fill="rgba(124,58,237,0.2)" stroke="rgba(124,58,237,0.6)" strokeWidth="2" />
              <path d="M40 18L58 27V38C58 49.5 50.5 59.5 40 63C29.5 59.5 22 49.5 22 38V27L40 18Z"
                fill="rgba(59,130,246,0.15)" stroke="rgba(59,130,246,0.5)" strokeWidth="1.5" />
              <path d="M30 40L37 47L52 33" stroke="#a78bfa" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Screen 2: Repository Submission ─────────────────────────────────────────

function RepositoryScreen({
  navigate,
  onSelectInput,
}: {
  navigate: (s: Screen) => void
  onSelectInput: (input: AssessmentInput) => void
}) {
  const [repoUrl, setRepoUrl] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState('')
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const selectZipFile = (file: File) => {
    setError('')

    if (!file.name.toLowerCase().endsWith('.zip')) {
      setSelectedFile(null)
      setError('Please select a ZIP repository archive.')
      return
    }

    const maxSize = 50 * 1024 * 1024

    if (file.size > maxSize) {
      setSelectedFile(null)
      setError('ZIP file must not exceed 50 MB.')
      return
    }

    setSelectedFile(file)
    setRepoUrl('')
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setDragging(false)

    const file = e.dataTransfer.files?.[0]

    if (file) {
      selectZipFile(file)
    }
  }

  const handleGitHubChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setRepoUrl(e.target.value)
    setSelectedFile(null)
    setError('')
  }

  const handleNext = () => {
    const trimmedUrl = repoUrl.trim()

    if (selectedFile) {
      onSelectInput({
        type: 'ZIP',
        file: selectedFile,
      })
      navigate('config')
      return
    }

    if (trimmedUrl) {
      try {
        const parsed = new URL(trimmedUrl)

        if (
          parsed.protocol !== 'https:' ||
          parsed.hostname !== 'github.com'
        ) {
          setError('Enter a valid public GitHub repository URL.')
          return
        }

        const parts = parsed.pathname
          .replace(/\/+$/, '')
          .split('/')
          .filter(Boolean)

        if (
          parts.length !== 2 ||
          parsed.search ||
          parsed.hash
        ) {
          setError(
            'Use a repository URL such as https://github.com/owner/repository.',
          )
          return
        }
      } catch {
        setError('Enter a valid public GitHub repository URL.')
        return
      }

      onSelectInput({
        type: 'GITHUB',
        repositoryUrl: trimmedUrl,
      })
      navigate('config')
      return
    }

    setError(
      'Enter a public GitHub repository URL or select a ZIP file.',
    )
  }

  return (
    <div style={{ flex: 1, padding: '40px 48px', overflowY: 'auto' }}>
      <div style={{ maxWidth: 640, margin: '0 auto' }}>
        <button
          onClick={() => navigate('home')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: '#64748b',
            fontSize: 13,
            marginBottom: 24,
            padding: 0,
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 14 14"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          >
            <path d="M9 2L4 7l5 5" />
          </svg>
          Home
        </button>

        <h1
          style={{
            fontSize: 24,
            fontWeight: 700,
            color: '#e2e8f0',
            margin: '0 0 6px',
          }}
        >
          Submit Repository
        </h1>

        <p
          style={{
            fontSize: 13,
            color: '#64748b',
            margin: '0 0 36px',
          }}
        >
          Submit a public GitHub repository or upload a ZIP archive to begin the
          security assessment.
        </p>

        <Card style={{ padding: 28, marginBottom: 16 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              marginBottom: 18,
            }}
          >
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <circle cx="9" cy="9" r="8" fill="#24292e" stroke="#30363d" />
              <path
                d="M9 4.5A4.5 4.5 0 0 0 9 13.5a4.5 4.5 0 0 0 0-9z"
                fill="white"
              />
            </svg>

            <span
              style={{
                fontSize: 13,
                fontWeight: 600,
                color: '#e2e8f0',
              }}
            >
              Option 1: Public GitHub Repository
            </span>
          </div>

          <input
            type="text"
            placeholder="https://github.com/username/repository"
            value={repoUrl}
            onChange={handleGitHubChange}
            style={{
              width: '100%',
              padding: '10px 14px',
              background: 'var(--bg-surface-2)',
              border: '1px solid var(--border-strong)',
              borderRadius: 8,
              color: '#e2e8f0',
              fontSize: 13,
              fontFamily: "'JetBrains Mono', monospace",
              outline: 'none',
              boxSizing: 'border-box',
            }}
          />

          <p
            style={{
              margin: '8px 0 0',
              fontSize: 11,
              color: '#64748b',
            }}
          >
            Public GitHub repositories are supported. Private repositories are
            not supported yet.
          </p>
        </Card>

        <div
          style={{
            textAlign: 'center',
            fontSize: 11,
            color: '#475569',
            margin: '10px 0',
            fontWeight: 600,
          }}
        >
          OR
        </div>

        <Card style={{ padding: 28, marginBottom: 16 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              marginBottom: 18,
            }}
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 18 18"
              fill="none"
              stroke="#64748b"
              strokeWidth="1.5"
            >
              <path
                d="M9 2v9M5 7l4 4 4-4"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <path
                d="M3 13v2a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-2"
                strokeLinecap="round"
              />
            </svg>

            <span
              style={{
                fontSize: 13,
                fontWeight: 600,
                color: '#e2e8f0',
              }}
            >
              Option 2: Upload Repository (ZIP)
            </span>
          </div>

          <input
            ref={fileInputRef}
            type="file"
            accept=".zip,application/zip"
            style={{ display: 'none' }}
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) {
                selectZipFile(file)
              }
            }}
          />

          <div
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => {
              e.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            style={{
              border: `2px dashed ${
                dragging
                  ? '#7c3aed'
                  : selectedFile
                    ? '#22c55e'
                    : 'var(--border-strong)'
              }`,
              borderRadius: 10,
              padding: '36px 24px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 8,
              background: dragging
                ? 'rgba(124,58,237,0.05)'
                : selectedFile
                  ? 'rgba(34,197,94,0.04)'
                  : 'transparent',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
          >
            {selectedFile ? (
              <>
                <div
                  style={{
                    width: 34,
                    height: 34,
                    borderRadius: '50%',
                    background: 'rgba(34,197,94,0.12)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <svg
                    width="16"
                    height="16"
                    viewBox="0 0 16 16"
                    fill="none"
                    stroke="#22c55e"
                    strokeWidth="2"
                  >
                    <path
                      d="M3 8l3 3 7-7"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>

                <p
                  style={{
                    margin: 0,
                    fontSize: 13,
                    color: '#e2e8f0',
                    fontWeight: 600,
                    overflowWrap: 'anywhere',
                    textAlign: 'center',
                  }}
                >
                  {selectedFile.name}
                </p>

                <p
                  style={{
                    margin: 0,
                    fontSize: 11,
                    color: '#64748b',
                  }}
                >
                  {(selectedFile.size / 1024 / 1024).toFixed(2)} MB · Click to
                  replace
                </p>
              </>
            ) : (
              <>
                <svg
                  width="32"
                  height="32"
                  viewBox="0 0 32 32"
                  fill="none"
                  stroke="#64748b"
                  strokeWidth="1.5"
                >
                  <path
                    d="M16 4v16M8 12l8-8 8 8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M4 24v2a2 2 0 0 0 2 2h20a2 2 0 0 0 2-2v-2"
                    strokeLinecap="round"
                  />
                </svg>

                <p
                  style={{
                    margin: 0,
                    fontSize: 13,
                    color: '#94a3b8',
                    fontWeight: 500,
                  }}
                >
                  Drag and drop ZIP file here
                </p>

                <p
                  style={{
                    margin: 0,
                    fontSize: 12,
                    color: '#64748b',
                  }}
                >
                  or click to browse
                </p>

                <p
                  style={{
                    margin: '8px 0 0',
                    fontSize: 11,
                    color: '#475569',
                  }}
                >
                  Maximum file size: 50 MB
                </p>
              </>
            )}
          </div>
        </Card>

        {error && (
          <div
            style={{
              padding: '11px 14px',
              marginBottom: 16,
              borderRadius: 8,
              border: '1px solid rgba(239,68,68,0.25)',
              background: 'rgba(239,68,68,0.07)',
              color: '#fca5a5',
              fontSize: 12,
            }}
          >
            {error}
          </div>
        )}

        <Card
          style={{
            padding: 20,
            marginBottom: 32,
            background: 'rgba(124,58,237,0.05)',
            border: '1px solid rgba(124,58,237,0.15)',
          }}
        >
          <div
            style={{
              display: 'flex',
              gap: 12,
              alignItems: 'flex-start',
            }}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              stroke="#a78bfa"
              strokeWidth="1.5"
              style={{
                flexShrink: 0,
                marginTop: 1,
              }}
            >
              <path d="M8 1L13 3.5V7C13 10.5 10.5 13.5 8 14.5C5.5 13.5 3 10.5 3 7V3.5L8 1Z" />
            </svg>

            <div>
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: '#a78bfa',
                  marginBottom: 4,
                }}
              >
                Privacy Notice
              </div>

              <div
                style={{
                  fontSize: 12,
                  color: '#64748b',
                  lineHeight: 1.6,
                }}
              >
                Repository contents are processed temporarily and automatically
                deleted after assessment. Source code is not permanently stored.
              </div>
            </div>
          </div>
        </Card>

        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
          }}
        >
          <Button onClick={handleNext}>
            Next
            <svg
              width="14"
              height="14"
              viewBox="0 0 14 14"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
            >
              <path d="M3 7h8M7 3l4 4-4 4" />
            </svg>
          </Button>
        </div>
      </div>
    </div>
  )
}


// ─── Screen 3: Assessment Review ─────────────────────────────────────────────

const ASSESSMENT_CHECKS = [
  {
    label: 'Source Code Analysis',
    desc: 'Rule-based static analysis examines source code for potentially insecure patterns.',
  },
  {
    label: 'Dependency Assessment',
    desc: 'Dependency manifests are checked for packages associated with known vulnerabilities.',
  },
  {
    label: 'Secret Detection',
    desc: 'Pattern-based checks identify likely hardcoded credentials and exposed secrets.',
  },
  {
    label: 'Configuration Assessment',
    desc: 'Security-relevant configuration files are checked using predefined rules.',
  },
]

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

function getGitHubRepositoryName(repositoryUrl: string) {
  try {
    const parsed = new URL(repositoryUrl)
    const parts = parsed.pathname
      .replace(/\/+$/, '')
      .replace(/\.git$/i, '')
      .split('/')
      .filter(Boolean)

    if (parts.length === 2) {
      return `${parts[0]}/${parts[1]}`
    }
  } catch {
    // RepositoryScreen already validates GitHub URLs.
  }

  return repositoryUrl
}

function ScanConfigScreen({
  navigate,
  assessmentInput,
  onStartAssessment,
}: {
  navigate: (s: Screen) => void
  assessmentInput: AssessmentInput | null
  onStartAssessment: () => void
}) {
  if (!assessmentInput) {
    return (
      <div style={{ flex: 1, padding: '40px 48px', overflowY: 'auto' }}>
        <div style={{ maxWidth: 760 }}>
          <h1
            style={{
              fontSize: 22,
              fontWeight: 700,
              color: '#e2e8f0',
              margin: '0 0 6px',
            }}
          >
            Assessment Review
          </h1>

          <p
            style={{
              fontSize: 13,
              color: '#64748b',
              margin: '0 0 28px',
            }}
          >
            No repository has been selected for assessment.
          </p>

          <Button onClick={() => navigate('repo')}>
            Select Repository
          </Button>
        </div>
      </div>
    )
  }

  const isGitHub = assessmentInput.type === 'GITHUB'

  const repositoryName = isGitHub
    ? getGitHubRepositoryName(assessmentInput.repositoryUrl)
    : assessmentInput.file.name

  const repositoryDetails = isGitHub
    ? [
        ['Input Type', 'Public GitHub Repository'],
        ['Repository', repositoryName],
        ['Repository URL', assessmentInput.repositoryUrl],
      ]
    : [
        ['Input Type', 'ZIP Archive'],
        ['File Name', assessmentInput.file.name],
        ['Archive Size', formatFileSize(assessmentInput.file.size)],
      ]

  return (
    <div
      style={{
        flex: 1,
        padding: '40px 48px',
        overflowY: 'auto',
      }}
    >
      <div style={{ maxWidth: 900 }}>
        <button
          onClick={() => navigate('repo')}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: '#64748b',
            fontSize: 13,
            marginBottom: 24,
            padding: 0,
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 14 14"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          >
            <path d="M9 2L4 7l5 5" />
          </svg>
          Change Repository
        </button>

        <h1
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: '#e2e8f0',
            margin: '0 0 6px',
          }}
        >
          Assessment Review
        </h1>

        <p
          style={{
            fontSize: 13,
            color: '#64748b',
            margin: '0 0 32px',
          }}
        >
          Review the selected repository and the security assessment mechanisms
          that Ligtask will run.
        </p>

        <Card
          style={{
            padding: 22,
            marginBottom: 20,
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontWeight: 700,
              color: '#94a3b8',
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              marginBottom: 18,
            }}
          >
            Repository Submission
          </div>

          {repositoryDetails.map(([label, value], index) => (
            <div
              key={label}
              style={{
                display: 'grid',
                gridTemplateColumns: '180px minmax(0, 1fr)',
                gap: 18,
                alignItems: 'start',
                paddingBottom:
                  index < repositoryDetails.length - 1 ? 14 : 0,
                marginBottom:
                  index < repositoryDetails.length - 1 ? 14 : 0,
                borderBottom:
                  index < repositoryDetails.length - 1
                    ? '1px solid var(--border)'
                    : 'none',
              }}
            >
              <span
                style={{
                  fontSize: 12,
                  color: '#64748b',
                }}
              >
                {label}
              </span>

              <span
                style={{
                  fontSize: 12,
                  color: '#e2e8f0',
                  fontWeight: 500,
                  fontFamily:
                    label === 'Repository URL'
                      ? "'JetBrains Mono', monospace"
                      : 'inherit',
                  overflowWrap: 'anywhere',
                }}
              >
                {value}
              </span>
            </div>
          ))}
        </Card>

        <Card
          style={{
            padding: 22,
            marginBottom: 20,
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontWeight: 700,
              color: '#94a3b8',
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
              marginBottom: 6,
            }}
          >
            Assessment Mechanisms
          </div>

          <p
            style={{
              fontSize: 12,
              color: '#64748b',
              margin: '0 0 20px',
              lineHeight: 1.6,
            }}
          >
            These mechanisms form the current Ligtask assessment pipeline and
            run automatically as part of the repository assessment.
          </p>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns:
                'repeat(auto-fit, minmax(280px, 1fr))',
              gap: 12,
            }}
          >
            {ASSESSMENT_CHECKS.map((check) => (
              <div
                key={check.label}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: 12,
                  padding: '14px 16px',
                  background: 'var(--bg-surface-2)',
                  borderRadius: 10,
                  border: '1px solid var(--border)',
                }}
              >
                <CheckIcon />

                <div>
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 600,
                      color: '#e2e8f0',
                      marginBottom: 3,
                    }}
                  >
                    {check.label}
                  </div>

                  <div
                    style={{
                      fontSize: 11,
                      color: '#64748b',
                      lineHeight: 1.5,
                    }}
                  >
                    {check.desc}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card
          style={{
            padding: 20,
            marginBottom: 28,
            background: 'rgba(124,58,237,0.05)',
            border: '1px solid rgba(124,58,237,0.15)',
          }}
        >
          <div
            style={{
              display: 'flex',
              gap: 12,
              alignItems: 'flex-start',
            }}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 16 16"
              fill="none"
              stroke="#a78bfa"
              strokeWidth="1.5"
              style={{
                flexShrink: 0,
                marginTop: 1,
              }}
            >
              <path d="M8 1L13 3.5V7C13 10.5 10.5 13.5 8 14.5C5.5 13.5 3 10.5 3 7V3.5L8 1Z" />
            </svg>

            <div>
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: '#a78bfa',
                  marginBottom: 4,
                }}
              >
                Privacy Processing
              </div>

              <div
                style={{
                  fontSize: 12,
                  color: '#64748b',
                  lineHeight: 1.6,
                }}
              >
                Repository contents are processed in a temporary workspace and
                automatically deleted after assessment. Source code and
                repository archives are not permanently stored by Ligtask.
              </div>
            </div>
          </div>
        </Card>

        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 12,
          }}
        >
          <Button
            variant="secondary"
            onClick={() => navigate('repo')}
          >
            Back
          </Button>

          <Button onClick={onStartAssessment}>
            Start Assessment
            <svg
              width="14"
              height="14"
              viewBox="0 0 14 14"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
            >
              <path d="M3 7h8M7 3l4 4-4 4" />
            </svg>
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Screen 4: Assessment in Progress ────────────────────────────────────────

function ScanningScreen({
  assessmentInput,
  error,
  onRetry,
  navigate,
}: {
  assessmentInput: AssessmentInput | null
  error: string
  onRetry: () => void
  navigate: (s: Screen) => void
}) {
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (error) return

    const startedAt = Date.now()

    const timer = window.setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAt) / 1000))
    }, 1000)

    return () => window.clearInterval(timer)
  }, [error])

  const fmt = (seconds: number) => {
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60

    return `${String(minutes).padStart(2, '0')}:${String(
      remainingSeconds,
    ).padStart(2, '0')}`
  }

  const inputLabel =
    assessmentInput?.type === 'GITHUB'
      ? getGitHubRepositoryName(assessmentInput.repositoryUrl)
      : assessmentInput?.type === 'ZIP'
        ? assessmentInput.file.name
        : 'No repository selected'

  if (error) {
    return (
      <div
        style={{
          flex: 1,
          padding: '40px 48px',
          overflowY: 'auto',
        }}
      >
        <div style={{ maxWidth: 760 }}>
          <h1
            style={{
              fontSize: 22,
              fontWeight: 700,
              color: '#e2e8f0',
              margin: '0 0 6px',
            }}
          >
            Assessment Failed
          </h1>

          <p
            style={{
              fontSize: 13,
              color: '#64748b',
              margin: '0 0 28px',
            }}
          >
            Ligtask could not complete the repository assessment.
          </p>

          <Card
            style={{
              padding: 22,
              marginBottom: 24,
              border: '1px solid rgba(239,68,68,0.25)',
              background: 'rgba(239,68,68,0.05)',
            }}
          >
            <div
              style={{
                fontSize: 12,
                fontWeight: 700,
                color: '#fca5a5',
                marginBottom: 8,
              }}
            >
              Error
            </div>

            <div
              style={{
                color: '#94a3b8',
                fontSize: 12,
                lineHeight: 1.65,
                overflowWrap: 'anywhere',
              }}
            >
              {error}
            </div>
          </Card>

          <div
            style={{
              display: 'flex',
              gap: 12,
            }}
          >
            <Button
              variant="secondary"
              onClick={() => navigate('repo')}
            >
              Change Repository
            </Button>

            <Button onClick={onRetry}>
              Retry Assessment
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div
      style={{
        flex: 1,
        padding: '40px 48px',
        overflowY: 'auto',
      }}
    >
      <div style={{ maxWidth: 900 }}>
        <h1
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: '#e2e8f0',
            margin: '0 0 6px',
          }}
        >
          Assessment in Progress
        </h1>

        <p
          style={{
            fontSize: 13,
            color: '#64748b',
            margin: '0 0 32px',
          }}
        >
          Ligtask is processing and assessing the selected repository.
        </p>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns:
              'minmax(0, 1.25fr) minmax(280px, 0.75fr)',
            gap: 24,
          }}
        >
          <Card style={{ padding: 28 }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 16,
                marginBottom: 24,
              }}
            >
              <div
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: '50%',
                  background: 'rgba(124,58,237,0.12)',
                  border: '1px solid rgba(124,58,237,0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <div
                  style={{
                    width: 18,
                    height: 18,
                    borderRadius: '50%',
                    border: '2px solid #7c3aed',
                    borderTopColor: 'transparent',
                    animation: 'spin 0.8s linear infinite',
                  }}
                />
              </div>

              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    color: '#e2e8f0',
                    fontSize: 14,
                    fontWeight: 700,
                    marginBottom: 4,
                  }}
                >
                  Running repository assessment
                </div>

                <div
                  style={{
                    color: '#64748b',
                    fontSize: 12,
                    overflowWrap: 'anywhere',
                  }}
                >
                  {inputLabel}
                </div>
              </div>
            </div>

            <div
              style={{
                padding: '14px 16px',
                borderRadius: 10,
                background: 'var(--bg-surface-2)',
                border: '1px solid var(--border)',
                color: '#64748b',
                fontSize: 12,
                lineHeight: 1.65,
              }}
            >
              The backend currently returns the assessment only after the full
              pipeline completes, so Ligtask does not display a fabricated
              percentage or claim that a specific scanner has finished.
            </div>

            <div
              style={{
                marginTop: 20,
                display: 'grid',
                gridTemplateColumns:
                  'repeat(auto-fit, minmax(220px, 1fr))',
                gap: 10,
              }}
            >
              {ASSESSMENT_CHECKS.map((check) => (
                <div
                  key={check.label}
                  style={{
                    display: 'flex',
                    gap: 10,
                    alignItems: 'flex-start',
                    padding: '12px 14px',
                    borderRadius: 9,
                    background: 'rgba(124,58,237,0.04)',
                    border: '1px solid var(--border)',
                  }}
                >
                  <div
                    style={{
                      width: 7,
                      height: 7,
                      borderRadius: '50%',
                      background: '#7c3aed',
                      marginTop: 5,
                      flexShrink: 0,
                    }}
                  />

                  <div>
                    <div
                      style={{
                        color: '#cbd5e1',
                        fontSize: 12,
                        fontWeight: 600,
                      }}
                    >
                      {check.label}
                    </div>

                    <div
                      style={{
                        color: '#475569',
                        fontSize: 10,
                        lineHeight: 1.45,
                        marginTop: 2,
                      }}
                    >
                      Included in the assessment pipeline
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 20,
            }}
          >
            <Card
              style={{
                padding: 28,
                textAlign: 'center',
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  color: '#64748b',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  fontWeight: 700,
                  marginBottom: 10,
                }}
              >
                Elapsed Time
              </div>

              <div
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  color: '#e2e8f0',
                  fontSize: 32,
                  fontWeight: 700,
                }}
              >
                {fmt(elapsed)}
              </div>

              <div
                style={{
                  color: '#475569',
                  fontSize: 11,
                  marginTop: 8,
                  lineHeight: 1.5,
                }}
              >
                Please keep this page open while the request is being processed.
              </div>
            </Card>

            <Card
              style={{
                padding: 20,
                background: 'rgba(124,58,237,0.05)',
                border: '1px solid rgba(124,58,237,0.15)',
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  color: '#a78bfa',
                  fontWeight: 600,
                  marginBottom: 5,
                }}
              >
                Privacy Processing
              </div>

              <div
                style={{
                  fontSize: 11,
                  color: '#64748b',
                  lineHeight: 1.6,
                }}
              >
                Repository contents are processed temporarily and automatically
                deleted after assessment. Source code is not permanently stored.
              </div>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Root App ─────────────────────────────────────────────────────────────────

type AssessmentStartResponse = {
  assessment_id: string
}

function getErrorMessage(error: unknown) {
  if (error instanceof Error && error.message.trim()) {
    return error.message
  }

  return 'An unexpected error occurred while processing the assessment.'
}

export default function App() {
  const [screen, setScreen] = useState<Screen>('home')

  const [assessmentInput, setAssessmentInput] =
    useState<AssessmentInput | null>(null)

  const [assessmentId, setAssessmentId] =
    useState<string | null>(null)

  const [selectedFinding, setSelectedFinding] =
    useState<AssessmentFinding | null>(null)

  const [assessmentError, setAssessmentError] =
    useState('')

  const [assessmentRunning, setAssessmentRunning] =
    useState(false)

  const navigate = (nextScreen: Screen) => {
    setScreen(nextScreen)
  }

  const openAssessment = (id: string) => {
    setAssessmentId(id)
    setSelectedFinding(null)
    setAssessmentError('')
    setScreen('results')
  }

  const openFinding = (
    finding: AssessmentFinding,
  ) => {
    setSelectedFinding(finding)
    setScreen('detail')
  }

  const startAssessment = async () => {
    if (!assessmentInput || assessmentRunning) {
      return
    }

    setAssessmentError('')
    setAssessmentRunning(true)
    setSelectedFinding(null)
    setAssessmentId(null)
    setScreen('scanning')

    try {
      let response: AssessmentStartResponse

      if (assessmentInput.type === 'ZIP') {
        response =
          await uploadRepository<AssessmentStartResponse>(
            assessmentInput.file,
          )
      } else {
        response =
          await assessGitHubRepository<AssessmentStartResponse>(
            assessmentInput.repositoryUrl,
          )
      }

      if (!response?.assessment_id) {
        throw new Error(
          'The backend completed the request but did not return an assessment ID.',
        )
      }

      setAssessmentId(response.assessment_id)
      setAssessmentError('')
      setScreen('results')
    } catch (error) {
      setAssessmentError(getErrorMessage(error))
      setScreen('scanning')
    } finally {
      setAssessmentRunning(false)
    }
  }

  return (
    <div
      style={{
        display: 'flex',
        minHeight: '100vh',
        background: 'var(--bg-base)',
      }}
    >
      <Sidebar
        current={screen}
        navigate={navigate}
      />

      <main
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          minHeight: '100vh',
          overflowX: 'hidden',
        }}
      >
        {screen === 'home' && (
          <HomeScreen navigate={navigate} />
        )}

        {screen === 'repo' && (
          <RepositoryScreen
            navigate={navigate}
            onSelectInput={(input) => {
              setAssessmentInput(input)
              setAssessmentError('')
            }}
          />
        )}

        {screen === 'config' && (
          <ScanConfigScreen
            navigate={navigate}
            assessmentInput={assessmentInput}
            onStartAssessment={startAssessment}
          />
        )}

        {screen === 'scanning' && (
          <ScanningScreen
            navigate={navigate}
            assessmentInput={assessmentInput}
            error={assessmentError}
            onRetry={startAssessment}
          />
        )}

        {screen === 'history' && (
          <HistoryScreen
            navigate={navigate}
            onOpenAssessment={openAssessment}
          />
        )}

        {screen === 'results' &&
          assessmentId !== null && (
            <AssessmentResultsScreen
              assessmentId={assessmentId}
              navigate={navigate}
              onOpenFinding={openFinding}
            />
          )}

        {screen === 'results' &&
          assessmentId === null && (
            <div
              style={{
                padding: '40px 48px',
                color: '#94a3b8',
              }}
            >
              No assessment selected.
            </div>
          )}

        {screen === 'detail' &&
          selectedFinding !== null && (
            <RealFindingDetailScreen
              finding={selectedFinding}
              onBack={() => navigate('results')}
            />
          )}
      </main>
    </div>
  )
}
