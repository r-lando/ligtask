import HistoryScreen from './pages/HistoryScreen'
import { useState, useEffect, useRef } from 'react'
import Sidebar, { type Screen } from './components/Sidebar'

// ─── Types ────────────────────────────────────────────────────────────────────


type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

interface Finding {
  id: string
  title: string
  severity: Severity
  category: string
  file: string
  status: string
  overview: string
  codeSnippet: string
  whyProblem: string
  recommendedFix: string
  lineNumber: number
}

// ─── Sample Data ──────────────────────────────────────────────────────────────

const FINDINGS: Finding[] = [
  {
    id: 'LGT-001',
    title: 'Hardcoded API Key Detected',
    severity: 'High',
    category: 'Sensitive Data Exposure',
    file: '/src/config/api.js',
    status: 'New',
    lineNumber: 12,
    overview:
      'An API key or secret was found hardcoded in the source code. Hardcoded secrets can be exposed if the code is publicly accessible.',
    codeSnippet: `const config = {\n  appName: "MyApp",\n  apiUrl: "https://api.example.com",\n  apiKey: "sk_live_51Hk...s1F9de", // Hardcoded key\n  timeout: 5000\n};`,
    whyProblem:
      'Hardcoded secrets can be easily extracted by attackers, leading to unauthorized access to external services and sensitive data.',
    recommendedFix:
      'Store secrets in environment variables or a secure secrets management solution.',
  },
  {
    id: 'LGT-002',
    title: 'Vulnerable Dependency (lodash)',
    severity: 'High',
    category: 'Use of Vulnerable Components',
    file: '/package.json',
    status: 'New',
    lineNumber: 14,
    overview:
      'The project depends on lodash version 4.17.15 which contains known prototype pollution vulnerabilities (CVE-2021-23337).',
    codeSnippet: `{\n  "dependencies": {\n    "express": "^4.18.2",\n    "lodash": "4.17.15",\n    "mongoose": "^7.0.0"\n  }\n}`,
    whyProblem:
      'Prototype pollution in lodash can allow attackers to modify JavaScript object prototypes, potentially enabling remote code execution or denial of service.',
    recommendedFix: 'Upgrade lodash to version 4.17.21 or later which patches this vulnerability.',
  },
  {
    id: 'LGT-003',
    title: "Unsafe eval() Usage",
    severity: 'Medium',
    category: 'Injection',
    file: '/src/utils/helper.js',
    status: 'New',
    lineNumber: 45,
    overview:
      "The eval() function is used to execute dynamically constructed code, which can be exploited if user input is included.",
    codeSnippet: `function processTemplate(template, data) {\n  // Dynamic evaluation - UNSAFE\n  return eval(\`with(data) { \${template} }\`);\n}`,
    whyProblem:
      "Using eval() with user-controlled input creates a code injection vulnerability allowing attackers to execute arbitrary JavaScript.",
    recommendedFix:
      'Replace eval() with safe alternatives like template literals, JSON.parse(), or a dedicated template engine.',
  },
  {
    id: 'LGT-004',
    title: 'Debug Mode Enabled',
    severity: 'Medium',
    category: 'Security Misconfiguration',
    file: '/config/default.js',
    status: 'New',
    lineNumber: 8,
    overview:
      'The application has debug mode enabled in configuration, which may expose stack traces and sensitive application internals.',
    codeSnippet: `module.exports = {\n  port: 3000,\n  debug: true,  // Should be false in production\n  logLevel: "verbose",\n  showErrors: true\n};`,
    whyProblem:
      'Debug mode exposes detailed error messages and stack traces that attackers can use to understand the application structure and find vulnerabilities.',
    recommendedFix:
      'Set debug to false in production environments and use environment-specific configuration files.',
  },
  {
    id: 'LGT-005',
    title: 'Missing Content Security Policy',
    severity: 'Low',
    category: 'Security Misconfiguration',
    file: '/src/views/index.ejs',
    status: 'New',
    lineNumber: 1,
    overview:
      'No Content-Security-Policy header is configured, leaving the application vulnerable to cross-site scripting attacks.',
    codeSnippet: `<!-- No CSP meta tag or header configured -->\n<!DOCTYPE html>\n<html>\n<head>\n  <title><%= title %></title>\n  <!-- Missing: <meta http-equiv="Content-Security-Policy" ...> -->\n</head>`,
    whyProblem:
      'Without a CSP, browsers allow loading resources from any origin, making XSS attacks easier to exploit.',
    recommendedFix:
      "Add a strict Content-Security-Policy header via middleware: app.use(helmet.contentSecurityPolicy()).",
  },
]

const SCAN_STEPS = [
  { label: 'Repository Processing', desc: 'Preparing and validating repository...' },
  { label: 'Structure Analysis', desc: 'Analyzing repository structure' },
  { label: 'Static Code Analysis', desc: 'Running rule-based code analysis' },
  { label: 'Dependency Analysis', desc: 'Checking for vulnerable dependencies' },
  { label: 'Configuration & Secret Checks', desc: 'Analyzing configs and detecting secrets' },
  { label: 'Report Generation', desc: 'Compiling results and generating report' },
]

const ACTIVITY_LINES = [
  'Cloning repository...',
  'Reading files and building index...',
  'Detecting project structure...',
  'Parsing JavaScript modules...',
  'Running SAST rules...',
  'Scanning dependency tree...',
  'Checking for exposed secrets...',
  'Analyzing configuration files...',
  'Generating vulnerability report...',
]

const VULN_CATEGORIES = [
  { name: 'Injection', count: 6, pct: 33 },
  { name: 'Security Misconfiguration', count: 4, pct: 22 },
  { name: 'Sensitive Data Exposure', count: 3, pct: 17 },
  { name: 'Broken Access Control', count: 3, pct: 17 },
  { name: 'Cryptographic Issues', count: 2, pct: 11 },
]

const SEV_DIST = [
  { label: 'Critical', count: 1, pct: 6, color: '#ef4444' },
  { label: 'High', count: 4, pct: 22, color: '#f97316' },
  { label: 'Medium', count: 7, pct: 39, color: '#eab308' },
  { label: 'Low', count: 6, pct: 33, color: '#22c55e' },
]

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

function SeverityBadge({ severity }: { severity: Severity }) {
  const colors: Record<Severity, { bg: string; color: string }> = {
    Critical: { bg: 'rgba(239,68,68,0.15)', color: '#ef4444' },
    High: { bg: 'rgba(249,115,22,0.15)', color: '#f97316' },
    Medium: { bg: 'rgba(234,179,8,0.15)', color: '#eab308' },
    Low: { bg: 'rgba(34,197,94,0.15)', color: '#22c55e' },
  }
  const { bg, color } = colors[severity]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 8px', borderRadius: 6,
      background: bg, color, fontSize: 11, fontWeight: 600,
    }}>
      {severity}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '3px 8px', borderRadius: 6,
      background: 'rgba(59,130,246,0.1)', color: '#60a5fa',
      fontSize: 11, fontWeight: 500,
    }}>
      {status}
    </span>
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

function CodeBlock({ code, highlightLine }: { code: string; highlightLine?: number }) {
  const lines = code.split('\n')
  return (
    <div style={{
      background: '#060a14', borderRadius: 10,
      border: '1px solid var(--border)',
      overflow: 'hidden',
      fontFamily: "'JetBrains Mono', monospace",
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        padding: '8px 14px',
        background: 'var(--bg-surface-2)',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }} />
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#eab308' }} />
        <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e' }} />
      </div>
      <div style={{ padding: '12px 0', overflowX: 'auto' }}>
        {lines.map((line, i) => {
          const lineNum = i + 9
          const isHighlight = lineNum === highlightLine
          return (
            <div key={i} style={{
              display: 'flex', gap: 0,
              background: isHighlight ? 'rgba(239,68,68,0.08)' : 'transparent',
              borderLeft: isHighlight ? '2px solid #ef4444' : '2px solid transparent',
            }}>
              <span style={{
                minWidth: 36, textAlign: 'right', paddingRight: 12, paddingLeft: 8,
                color: isHighlight ? '#ef4444' : '#334155',
                fontSize: 12, userSelect: 'none', flexShrink: 0,
              }}>
                {lineNum}
              </span>
              <span style={{ color: '#94a3b8', fontSize: 12, paddingRight: 16, whiteSpace: 'pre' }}>
                {line}
              </span>
            </div>
          )
        })}
      </div>
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
      desc: 'All processing is done in-memory. Your repository contents are never stored or saved.',
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

function RepositoryScreen({ navigate }: { navigate: (s: Screen) => void }) {
  const [repoUrl, setRepoUrl] = useState('')
  const [dragging, setDragging] = useState(false)

  return (
    <div style={{ flex: 1, padding: '40px 48px', overflowY: 'auto' }}>
      <div style={{ maxWidth: 640, margin: '0 auto' }}>
        <button
          onClick={() => navigate('home')}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'none', border: 'none', cursor: 'pointer',
            color: '#64748b', fontSize: 13, marginBottom: 24, padding: 0,
          }}
        >
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
            <path d="M9 2L4 7l5 5" />
          </svg>
          Submit Repository
        </button>

        <h1 style={{ fontSize: 24, fontWeight: 700, color: '#e2e8f0', margin: '0 0 6px' }}>Submit Repository</h1>
        <p style={{ fontSize: 13, color: '#64748b', margin: '0 0 36px' }}>
          Provide your repository details to begin security assessment.
        </p>

        <Card style={{ padding: 28, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <circle cx="9" cy="9" r="8" fill="#24292e" stroke="#30363d" />
              <path d="M9 4.5A4.5 4.5 0 0 0 9 13.5a4.5 4.5 0 0 0 0-9z" fill="white" />
              <path d="M9 4.5c-1.5 1.5-1.5 3.5 0 4.5 1.5 1 1.5 3 0 4.5" stroke="white" strokeWidth="0.5" />
            </svg>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>Option 1: GitHub Repository URL</span>
          </div>

          <input
            type="text"
            placeholder="https://github.com/username/repository"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            style={{
              width: '100%', padding: '10px 14px',
              background: 'var(--bg-surface-2)', border: '1px solid var(--border-strong)',
              borderRadius: 8, color: '#e2e8f0', fontSize: 13,
              fontFamily: "'JetBrains Mono', monospace", outline: 'none',
              boxSizing: 'border-box',
            }}
          />
          <p style={{ margin: '8px 0 0', fontSize: 11, color: '#64748b' }}>
            The repository must be public or accessible.
          </p>
        </Card>

        <Card style={{ padding: 28, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="#64748b" strokeWidth="1.5">
              <path d="M9 2v9M5 7l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M3 13v2a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-2" strokeLinecap="round" />
            </svg>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>Option 2: Upload Repository (ZIP)</span>
          </div>

          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false) }}
            style={{
              border: `2px dashed ${dragging ? '#7c3aed' : 'var(--border-strong)'}`,
              borderRadius: 10, padding: '36px 24px',
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
              background: dragging ? 'rgba(124,58,237,0.05)' : 'transparent',
              cursor: 'pointer', transition: 'all 0.15s',
            }}
          >
            <svg width="32" height="32" viewBox="0 0 32 32" fill="none" stroke="#64748b" strokeWidth="1.5">
              <path d="M16 4v16M8 12l8-8 8 8" strokeLinecap="round" strokeLinejoin="round" />
              <path d="M4 24v2a2 2 0 0 0 2 2h20a2 2 0 0 0 2-2v-2" strokeLinecap="round" />
            </svg>
            <p style={{ margin: 0, fontSize: 13, color: '#94a3b8', fontWeight: 500 }}>
              Drag and drop ZIP file here
            </p>
            <p style={{ margin: 0, fontSize: 12, color: '#64748b' }}>or click to browse</p>
            <p style={{ margin: '8px 0 0', fontSize: 11, color: '#334155' }}>Maximum file size: 100 MB</p>
          </div>
        </Card>

        <Card style={{ padding: 20, marginBottom: 32, background: 'rgba(124,58,237,0.05)', border: '1px solid rgba(124,58,237,0.15)' }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="#a78bfa" strokeWidth="1.5" style={{ flexShrink: 0, marginTop: 1 }}>
              <path d="M8 1L13 3.5V7C13 10.5 10.5 13.5 8 14.5C5.5 13.5 3 10.5 3 7V3.5L8 1Z" />
            </svg>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600, color: '#a78bfa', marginBottom: 4 }}>Privacy Notice</div>
              <div style={{ fontSize: 12, color: '#64748b', lineHeight: 1.6 }}>
                Your repository contents will be processed in-memory only. No source code or files will be permanently stored.
              </div>
            </div>
          </div>
        </Card>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button onClick={() => navigate('config')}>
            Next
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M3 7h8M7 3l4 4-4 4" />
            </svg>
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Screen 3: Scan Configuration ────────────────────────────────────────────

const SECURITY_CHECKS = [
  { label: 'Source Code Analysis', desc: 'Detect insecure code patterns (e.g., XSS, command injection)' },
  { label: 'Secret Detection', desc: 'Detect hardcoded secrets, API keys, and credentials' },
  { label: 'Dependency Analysis', desc: 'Check for known vulnerable open-source dependencies' },
  { label: 'Best Practices & Security Headers', desc: 'Identify missing security headers and best practice issues' },
  { label: 'Configuration Analysis', desc: 'Detect configuration files for security misconfigurations' },
  { label: 'File & Path Analysis', desc: 'Analyze for sensitive files, unsafe permissions, and exposures' },
]

const FILE_TREE = [
  { name: 'sample-project/', indent: 0 },
  { name: 'src/', indent: 1 },
  { name: 'routes/', indent: 2 },
  { name: 'controllers/', indent: 2 },
  { name: 'node_modules/', indent: 1 },
  { name: 'config/', indent: 1 },
  { name: 'tests/', indent: 1 },
  { name: 'package.json', indent: 1 },
  { name: '.env.example', indent: 1 },
]

function ScanConfigScreen({ navigate }: { navigate: (s: Screen) => void }) {
  const [checks, setChecks] = useState(SECURITY_CHECKS.map(() => true))

  return (
    <div style={{ flex: 1, padding: '40px 48px', overflowY: 'auto' }}>
      <div style={{ maxWidth: 900 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', margin: '0 0 6px' }}>Scan Configuration</h1>
        <p style={{ fontSize: 13, color: '#64748b', margin: '0 0 32px' }}>
          Review detected project information and analysis checks.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 28 }}>
          <Card style={{ padding: 22 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 18 }}>
              Repository Information
            </div>
            {[
              ['Repository', 'sample-project'],
              ['Detected Type', 'Node.js (Express)'],
              ['Primary Language', 'JavaScript'],
              ['Repository Size', '1,248 files (3.6 MB)'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14, paddingBottom: 14, borderBottom: '1px solid var(--border)' }}>
                <span style={{ fontSize: 12, color: '#64748b' }}>{k}</span>
                <span style={{ fontSize: 12, color: '#e2e8f0', fontWeight: 500 }}>{v}</span>
              </div>
            ))}
          </Card>

          <Card style={{ padding: 22 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 16 }}>
              Detected Structure
            </div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12 }}>
              {FILE_TREE.map((f, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 0', paddingLeft: f.indent * 14 }}>
                  <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                    {f.name.endsWith('/') ? (
                      <path d="M1 3h8v5H1z" fill="rgba(59,130,246,0.4)" stroke="#3b82f6" strokeWidth="0.8" />
                    ) : (
                      <path d="M1 1h6l2 2v6H1z" fill="rgba(124,58,237,0.3)" stroke="#7c3aed" strokeWidth="0.8" />
                    )}
                  </svg>
                  <span style={{ color: f.name.endsWith('/') ? '#93c5fd' : '#94a3b8', fontSize: 11 }}>{f.name}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>

        <Card style={{ padding: 22, marginBottom: 28 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>
            Security Checks to Run
          </div>
          <p style={{ fontSize: 12, color: '#64748b', margin: '0 0 20px' }}>
            We will perform the following rule-based static analysis:
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            {SECURITY_CHECKS.map((check, i) => (
              <div
                key={check.label}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 12, padding: '14px 16px',
                  background: 'var(--bg-surface-2)', borderRadius: 10,
                  border: '1px solid var(--border)',
                }}
              >
                <CheckIcon checked={checks[i]} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0', marginBottom: 3 }}>{check.label}</div>
                  <div style={{ fontSize: 11, color: '#64748b', lineHeight: 1.5 }}>{check.desc}</div>
                </div>
                <label style={{ cursor: 'pointer', flexShrink: 0, marginTop: 1 }}>
                  <input
                    type="checkbox"
                    checked={checks[i]}
                    onChange={() => setChecks((prev) => prev.map((v, j) => j === i ? !v : v))}
                    style={{ display: 'none' }}
                  />
                  <div style={{
                    width: 28, height: 16, borderRadius: 8, transition: 'all 0.2s',
                    background: checks[i] ? 'var(--accent-purple)' : 'var(--bg-surface-3)',
                    border: '1px solid var(--border-strong)',
                    position: 'relative',
                  }}>
                    <div style={{
                      position: 'absolute', top: 2, borderRadius: '50%',
                      width: 10, height: 10, background: '#fff', transition: 'all 0.2s',
                      left: checks[i] ? 14 : 2,
                    }} />
                  </div>
                </label>
              </div>
            ))}
          </div>
        </Card>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button onClick={() => navigate('scanning')}>
            Start Scan
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
              <path d="M3 7h8M7 3l4 4-4 4" />
            </svg>
          </Button>
        </div>
      </div>
    </div>
  )
}

// ─── Screen 4: Scanning in Progress ──────────────────────────────────────────

function ScanningScreen({ navigate }: { navigate: (s: Screen) => void }) {
  const [progress, setProgress] = useState(0)
  const [currentStep, setCurrentStep] = useState(0)
  const [activityIdx, setActivityIdx] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [done, setDone] = useState(false)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const prog = { value: 0 }
    timerRef.current = setInterval(() => {
      prog.value = Math.min(100, prog.value + 1.2)
      const p = prog.value
      setProgress(p)
      setElapsed((e) => e + 1)
      setCurrentStep(Math.min(5, Math.floor(p / 17)))
      setActivityIdx((a) => (a + 1) % ACTIVITY_LINES.length)
      if (p >= 100) {
        if (timerRef.current) clearInterval(timerRef.current)
        setDone(true)
      }
    }, 80)
    return () => { if (timerRef.current) clearInterval(timerRef.current) }
  }, [])

  const pct = Math.floor(progress)
  const r = 72
  const circ = 2 * Math.PI * r
  const dash = circ * (1 - pct / 100)

  const fmt = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return `${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`
  }

  return (
    <div style={{ flex: 1, padding: '40px 48px', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 6 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', margin: '0 0 6px' }}>Scanning in Progress</h1>
          <p style={{ fontSize: 13, color: '#64748b', margin: 0 }}>
            Please wait while we analyze your repository. This may take a few minutes.
          </p>
        </div>
        <div style={{
          padding: '6px 14px', borderRadius: 8,
          background: 'var(--bg-surface-2)', border: '1px solid var(--border)',
          fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#64748b',
        }}>
          Scan ID: 7f3a2b1c
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginTop: 32 }}>
        <Card style={{ padding: 28 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {SCAN_STEPS.map((step, i) => {
              const completed = i < currentStep
              const active = i === currentStep && !done
              const pending = i > currentStep

              return (
                <div key={step.label} style={{ display: 'flex', gap: 14, paddingBottom: i < SCAN_STEPS.length - 1 ? 20 : 0, position: 'relative' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                    <div style={{
                      width: 28, height: 28, borderRadius: '50%',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: completed || done
                        ? 'rgba(34,197,94,0.15)'
                        : active
                          ? 'rgba(124,58,237,0.2)'
                          : 'var(--bg-surface-3)',
                      border: `2px solid ${completed || done ? '#22c55e' : active ? '#7c3aed' : 'var(--border)'}`,
                      zIndex: 1,
                    }}>
                      {(completed || done) ? (
                        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                          <path d="M2 6L5 9L10 3" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      ) : active ? (
                        <div style={{
                          width: 8, height: 8, borderRadius: '50%',
                          border: '2px solid #7c3aed', borderTopColor: 'transparent',
                          animation: 'spin 0.8s linear infinite',
                        }} />
                      ) : (
                        <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--border-strong)' }} />
                      )}
                    </div>
                    {i < SCAN_STEPS.length - 1 && (
                      <div style={{
                        width: 2, flex: 1, marginTop: 4,
                        background: completed || done
                          ? 'rgba(34,197,94,0.4)'
                          : 'var(--border)',
                      }} />
                    )}
                  </div>
                  <div style={{ paddingTop: 3, paddingBottom: i < SCAN_STEPS.length - 1 ? 0 : 0 }}>
                    <div style={{
                      fontSize: 13, fontWeight: 600,
                      color: pending ? '#334155' : '#e2e8f0',
                    }}>
                      {step.label}
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                      {step.desc}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </Card>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <Card style={{ padding: 28, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <svg width="180" height="180" viewBox="0 0 180 180">
              <circle cx="90" cy="90" r={r} fill="none" stroke="var(--bg-surface-3)" strokeWidth="10" />
              <circle
                cx="90" cy="90" r={r} fill="none"
                stroke={done ? '#22c55e' : '#7c3aed'}
                strokeWidth="10"
                strokeLinecap="round"
                strokeDasharray={circ}
                strokeDashoffset={dash}
                transform="rotate(-90 90 90)"
                style={{ transition: 'stroke-dashoffset 0.1s, stroke 0.3s' }}
              />
              <text x="90" y="84" textAnchor="middle" fill="#e2e8f0" fontSize="28" fontWeight="700" fontFamily="Inter">
                {pct}%
              </text>
              <text x="90" y="104" textAnchor="middle" fill="#64748b" fontSize="12" fontFamily="Inter">
                {done ? 'Complete' : 'In Progress'}
              </text>
            </svg>

            {done && (
              <Button onClick={() => navigate('results')} style={{ marginTop: 16 }}>
                View Results
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <path d="M3 7h8M7 3l4 4-4 4" />
                </svg>
              </Button>
            )}
          </Card>

          <Card style={{ padding: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 14 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>Current Activity</span>
              <span style={{
                fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#64748b',
              }}>{fmt(elapsed)}</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {ACTIVITY_LINES.slice(Math.max(0, activityIdx - 2), activityIdx + 1).map((line, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{
                    width: 5, height: 5, borderRadius: '50%', flexShrink: 0,
                    background: i === Math.min(2, activityIdx) ? '#7c3aed' : '#334155',
                  }} />
                  <span style={{ fontSize: 12, color: i === Math.min(2, activityIdx) ? '#94a3b8' : '#334155' }}>
                    {line}
                  </span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      <div style={{
        marginTop: 28, padding: '14px 20px',
        background: 'rgba(124,58,237,0.05)', borderRadius: 10,
        border: '1px solid rgba(124,58,237,0.12)',
        display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="#7c3aed" strokeWidth="1.5">
          <path d="M7 1L11.5 3.25V6.5C11.5 9.25 9.5 11.75 7 12.5C4.5 11.75 2.5 9.25 2.5 6.5V3.25L7 1Z" />
        </svg>
        <span style={{ fontSize: 12, color: '#64748b' }}>
          Your repository is being processed securely in-memory and will be discarded after the assessment.
        </span>
      </div>

    </div>
  )
}

// ─── Screen 5: Assessment Results ────────────────────────────────────────────

function DonutChart() {
  const total = 18
  const r = 52
  const circ = 2 * Math.PI * r
  let offset = 0

  return (
    <svg width="140" height="140" viewBox="0 0 140 140">
      <circle cx="70" cy="70" r={r} fill="none" stroke="var(--bg-surface-3)" strokeWidth="16" />
      {SEV_DIST.map((s) => {
        const len = circ * (s.count / total)
        const seg = (
          <circle
            key={s.label}
            cx="70" cy="70" r={r}
            fill="none"
            stroke={s.color}
            strokeWidth="16"
            strokeLinecap="butt"
            strokeDasharray={`${len} ${circ - len}`}
            strokeDashoffset={-offset}
            transform="rotate(-90 70 70)"
          />
        )
        offset += len
        return seg
      })}
      <text x="70" y="65" textAnchor="middle" fill="#e2e8f0" fontSize="22" fontWeight="700" fontFamily="Inter">{total}</text>
      <text x="70" y="81" textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="Inter">Total</text>
    </svg>
  )
}

function ResultsScreen({ navigate, onFinding }: { navigate: (s: Screen) => void; onFinding: (idx: number) => void }) {
  return (
    <div style={{ flex: 1, padding: '40px 48px', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 28 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#e2e8f0', margin: '0 0 4px' }}>Assessment Results</h1>
          <p style={{ fontSize: 12, color: '#64748b', margin: 0 }}>
            Completed on May 15, 2025 &nbsp;&bull;&nbsp; 10:42 AM
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <Button variant="secondary" size="sm">
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
              <path d="M6.5 1v8M2.5 5.5l4 4 4-4" />
              <path d="M1.5 11h10" />
            </svg>
            Download Report
          </Button>
          <Button variant="secondary" size="sm">
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
              <circle cx="9" cy="2" r="1.5" />
              <circle cx="9" cy="11" r="1.5" />
              <circle cx="2" cy="6.5" r="1.5" />
              <path d="M7.5 2.7L3.5 5.8M7.5 10.3L3.5 7.2" />
            </svg>
            Share
          </Button>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          {
            label: 'Overall Risk Level', value: 'High', sub: 'The repository has security issues that should be addressed.',
            valueStyle: { color: '#f97316', fontSize: 28, fontWeight: 800 },
            icon: <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#f97316" strokeWidth="1.5"><path d="M10 3L18 17H2L10 3z" /><path d="M10 9v3M10 14v.5" strokeLinecap="round" /></svg>,
          },
          {
            label: 'Total Findings', value: '18', sub: 'Issues identified',
            valueStyle: { color: '#e2e8f0', fontSize: 28, fontWeight: 800 },
            icon: <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#3b82f6" strokeWidth="1.5"><path d="M10 2A8 8 0 1 0 10 18A8 8 0 0 0 10 2Z" /><path d="M10 9v5M10 6v.5" strokeLinecap="round" /></svg>,
          },
          {
            label: 'Files Scanned', value: '1,248', sub: 'Total files analyzed',
            valueStyle: { color: '#e2e8f0', fontSize: 28, fontWeight: 800 },
            icon: <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#06b6d4" strokeWidth="1.5"><path d="M5 3h7l4 4v10H5V3z" strokeLinecap="round" strokeLinejoin="round" /><path d="M12 3v4h4" /></svg>,
          },
          {
            label: 'Checks Performed', value: '6', sub: 'Security checks',
            valueStyle: { color: '#e2e8f0', fontSize: 28, fontWeight: 800 },
            icon: <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="#22c55e" strokeWidth="1.5"><path d="M10 2L16 5.5V10C16 14.5 13.5 17.5 10 18.5C6.5 17.5 4 14.5 4 10V5.5L10 2Z" /><path d="M7 10L9 12L13 8" strokeLinecap="round" strokeLinejoin="round" /></svg>,
          },
        ].map((stat) => (
          <Card key={stat.label} style={{ padding: '20px 22px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: '#64748b', fontWeight: 500, lineHeight: 1.4, maxWidth: 100 }}>{stat.label}</span>
              {stat.icon}
            </div>
            <div style={stat.valueStyle}>{stat.value}</div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>{stat.sub}</div>
          </Card>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 20, marginBottom: 24 }}>
        <Card style={{ padding: 22, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 16, alignSelf: 'flex-start' }}>
            Findings by Severity
          </div>
          <DonutChart />
          <div style={{ width: '100%', marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {SEV_DIST.map((s) => (
              <div key={s.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 3, background: s.color }} />
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>{s.label}</span>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: s.color }}>{s.count}</span>
                  <span style={{ fontSize: 11, color: '#334155' }}>({s.pct}%)</span>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card style={{ padding: 22 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 20 }}>
            Top Vulnerability Categories
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {VULN_CATEGORIES.map((cat) => (
              <div key={cat.name}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>{cat.name}</span>
                  <span style={{ fontSize: 12, color: '#64748b' }}>{cat.count} ({cat.pct}%)</span>
                </div>
                <div style={{ height: 6, borderRadius: 3, background: 'var(--bg-surface-3)', overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', borderRadius: 3,
                    width: `${cat.pct}%`,
                    background: cat.pct > 25 ? '#ef4444' : cat.pct > 20 ? '#f97316' : '#eab308',
                    transition: 'width 0.5s',
                  }} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card style={{ padding: 22 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: '#94a3b8', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 18 }}>
          Recent Findings
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['ID', 'Title', 'Severity', 'Category', 'File', 'Status'].map((h) => (
                <th key={h} style={{
                  textAlign: 'left', fontSize: 11, fontWeight: 600, color: '#64748b',
                  padding: '0 12px 12px', borderBottom: '1px solid var(--border)',
                  letterSpacing: '0.04em', textTransform: 'uppercase',
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {FINDINGS.map((f, i) => (
              <tr
                key={f.id}
                onClick={() => onFinding(i)}
                style={{ cursor: 'pointer' }}
                onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--bg-surface-2)')}
                onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
              >
                <td style={{ padding: '12px', fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#64748b', borderBottom: '1px solid var(--border)' }}>{f.id}</td>
                <td style={{ padding: '12px', fontSize: 12, color: '#e2e8f0', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>{f.title}</td>
                <td style={{ padding: '12px', borderBottom: '1px solid var(--border)' }}><SeverityBadge severity={f.severity} /></td>
                <td style={{ padding: '12px', fontSize: 12, color: '#64748b', borderBottom: '1px solid var(--border)' }}>{f.category}</td>
                <td style={{ padding: '12px', fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#64748b', borderBottom: '1px solid var(--border)' }}>{f.file}</td>
                <td style={{ padding: '12px', borderBottom: '1px solid var(--border)' }}><StatusBadge status={f.status} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ marginTop: 20, display: 'flex', justifyContent: 'center' }}>
          <Button variant="secondary">View All Findings</Button>
        </div>
      </Card>
    </div>
  )
}

// ─── Screen 6: Finding Details ────────────────────────────────────────────────

function FindingDetailScreen({ findingIdx, onBack, onNav }: {
  findingIdx: number
  onBack: () => void
  onNav: (dir: 1 | -1) => void
}) {
  const f = FINDINGS[findingIdx]

  return (
    <div style={{ flex: 1, padding: '40px 48px', overflowY: 'auto' }}>
      <div style={{ maxWidth: 740 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 28 }}>
          <button
            onClick={onBack}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#64748b', fontSize: 13, padding: 0,
            }}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
              <path d="M9 2L4 7l5 5" />
            </svg>
            Back to Results
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <Button variant="secondary" size="sm" onClick={() => onNav(-1)} disabled={findingIdx === 0}>
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                <path d="M8 2L4 6l4 4" />
              </svg>
              Previous
            </Button>
            <Button variant="secondary" size="sm" onClick={() => onNav(1)} disabled={findingIdx === FINDINGS.length - 1}>
              Next
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                <path d="M4 2l4 4-4 4" />
              </svg>
            </Button>
          </div>
        </div>

        <Card style={{ padding: '24px 28px', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <SeverityBadge severity={f.severity} />
              <h2 style={{ fontSize: 18, fontWeight: 700, color: '#e2e8f0', margin: 0 }}>{f.title}</h2>
            </div>
            <span style={{
              fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#334155',
              padding: '4px 10px', background: 'var(--bg-surface-2)', borderRadius: 6, border: '1px solid var(--border)',
            }}>
              ID: {f.id}
            </span>
          </div>

          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 10 }}>
              Overview
            </div>
            <p style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.7, margin: 0 }}>{f.overview}</p>
          </div>

          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 10 }}>
              Affected File
            </div>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 14px', background: 'var(--bg-surface-2)', borderRadius: 8, border: '1px solid var(--border)',
            }}>
              <span style={{ fontSize: 12, fontFamily: "'JetBrains Mono', monospace", color: '#93c5fd' }}>
                {f.file}:{f.lineNumber}
              </span>
              <Button variant="ghost" size="sm">
                <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                  <rect x="1" y="1" width="10" height="10" rx="1.5" />
                  <path d="M4 4h4M4 6h4M4 8h2" />
                </svg>
                View File
              </Button>
            </div>
          </div>

          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 10 }}>
              Code Snippet
            </div>
            <CodeBlock code={f.codeSnippet} highlightLine={f.lineNumber} />
          </div>

          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 10 }}>
              Why is this a problem?
            </div>
            <p style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.7, margin: 0 }}>{f.whyProblem}</p>
          </div>

          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 10 }}>
              Recommended Fix
            </div>
            <div style={{
              padding: '14px 16px', background: 'rgba(34,197,94,0.05)', borderRadius: 8,
              border: '1px solid rgba(34,197,94,0.15)',
            }}>
              <p style={{ fontSize: 13, color: '#86efac', lineHeight: 1.7, margin: 0 }}>{f.recommendedFix}</p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{ padding: '14px 18px', background: 'var(--bg-surface-2)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>Category</div>
              <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 500 }}>{f.category}</div>
            </div>
            <div style={{ padding: '14px 18px', background: 'var(--bg-surface-2)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>Severity</div>
              <SeverityBadge severity={f.severity} />
            </div>
            <div style={{ padding: '14px 18px', background: 'var(--bg-surface-2)', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#64748b', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 6 }}>Status</div>
              <StatusBadge status={f.status} />
            </div>
          </div>
        </Card>
      </div>
    </div>
  )
}

// ─── Root App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [screen, setScreen] = useState<Screen>('home')
  const [assessmentId, setAssessmentId] = useState<string | null>(null)
  const [findingIdx, setFindingIdx] = useState(0)

  const navigate = (s: Screen) => setScreen(s)

  const openAssessment = (id: string) => {
    setAssessmentId(id)
    setScreen('results')
  }

  const openFinding = (idx: number) => {
    setFindingIdx(idx)
    setScreen('detail')
  }

  const navFinding = (dir: 1 | -1) => {
    setFindingIdx((i) => Math.max(0, Math.min(FINDINGS.length - 1, i + dir)))
  }

  void assessmentId

  const screenLabels: Partial<Record<Screen, string>> = {
    home: 'Home',
    repo: 'New Assessment',
    config: 'New Assessment',
    scanning: 'New Assessment',
    history: 'Scan History',
    results: 'Assessment Results',
    detail: 'Finding Details',
  }

  void screenLabels

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-base)' }}>
      <Sidebar current={screen} navigate={navigate} />

      <main
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          minHeight: '100vh',
          overflowX: 'hidden',
        }}
      >
        {screen === 'home' && <HomeScreen navigate={navigate} />}

        {screen === 'repo' && (
          <RepositoryScreen navigate={navigate} />
        )}

        {screen === 'config' && (
          <ScanConfigScreen navigate={navigate} />
        )}

        {screen === 'scanning' && (
          <ScanningScreen navigate={navigate} />
        )}

        {screen === 'history' && (
          <HistoryScreen
            navigate={navigate}
            onOpenAssessment={openAssessment}
          />
        )}

        {screen === 'results' && (
          <ResultsScreen
            navigate={navigate}
            onFinding={openFinding}
          />
        )}

        {screen === 'detail' && (
          <FindingDetailScreen
            findingIdx={findingIdx}
            onBack={() => navigate('results')}
            onNav={navFinding}
          />
        )}
      </main>
    </div>
  )
}