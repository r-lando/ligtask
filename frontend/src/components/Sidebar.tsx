import type { ReactNode } from 'react'
import Logo from './Logo'

export type Screen =
  | 'home'
  | 'repo'
  | 'config'
  | 'scanning'
  | 'history'
  | 'results'
  | 'detail'
  | 'about'
  | 'privacy'

interface SidebarProps {
  current: Screen
  navigate: (screen: Screen) => void
}

interface SidebarItem {
  label: string
  screen: Screen
  icon: ReactNode
}

export default function Sidebar({
  current,
  navigate,
}: SidebarProps) {
  const items: SidebarItem[] = [
    {
      label: 'Home',
      screen: 'home',
      icon: (
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="currentColor"
        >
          <path d="M8 1L1 7h2v7h4v-4h2v4h4V7h2L8 1z" />
        </svg>
      ),
    },
    {
      label: 'New Assessment',
      screen: 'repo',
      icon: (
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
        >
          <circle cx="8" cy="8" r="6.5" />
          <path d="M8 5v6M5 8h6" />
        </svg>
      ),
    },
    {
      label: 'Scan History',
      screen: 'history',
      icon: (
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
        >
          <rect x="2" y="2" width="12" height="12" rx="2" />
          <path d="M5 6h6M5 9h4" />
        </svg>
      ),
    },
    {
      label: 'About',
      screen: 'about',
      icon: (
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
        >
          <circle cx="8" cy="8" r="6.5" />
          <path d="M8 7v5M8 5v.5" />
        </svg>
      ),
    },
    {
      label: 'Privacy',
      screen: 'privacy',
      icon: (
        <svg
          width="16"
          height="16"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
        >
          <path d="M8 1L13 3.5V7C13 10.5 10.5 13.5 8 14.5C5.5 13.5 3 10.5 3 7V3.5L8 1Z" />
        </svg>
      ),
    },
  ]

  const isActive = (screen: Screen) => {
  if (
    screen === 'repo' &&
    (
      current === 'repo' ||
      current === 'config' ||
      current === 'scanning'
    )
  ) {
    return true
  }

  if (
    screen === 'history' &&
    (
      current === 'history' ||
      current === 'results' ||
      current === 'detail'
    )
  ) {
    return true
  }

  return current === screen
}

  return (
    <aside
      style={{
        width: 200,
        minHeight: '100vh',
        flexShrink: 0,
        background: 'var(--bg-surface)',
        borderRight: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'column',
        padding: '20px 12px',
      }}
    >
      <div style={{ paddingBottom: 24, paddingLeft: 8 }}>
        <Logo />
      </div>

      <nav
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 2,
          flex: 1,
        }}
      >
        {items.map((item) => {
          const active = isActive(item.screen)

          return (
            <button
              key={item.label}
              onClick={() => navigate(item.screen)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 10px',
                borderRadius: 8,
                border: 'none',
                cursor: 'pointer',
                background: active
                  ? 'rgba(124, 58, 237, 0.15)'
                  : 'transparent',
                color: active ? '#a78bfa' : '#64748b',
                fontSize: 13,
                fontWeight: active ? 600 : 400,
                textAlign: 'left',
                width: '100%',
                transition: 'all 0.15s',
              }}
            >
              {item.icon}
              {item.label}
            </button>
          )
        })}
      </nav>

      <div
        style={{
          marginTop: 'auto',
          padding: '12px 10px',
          background: 'rgba(124, 58, 237, 0.08)',
          borderRadius: 10,
          border: '1px solid rgba(124, 58, 237, 0.15)',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginBottom: 6,
          }}
        >
          <svg
            width="12"
            height="12"
            viewBox="0 0 16 16"
            fill="none"
            stroke="#7c3aed"
            strokeWidth="1.5"
          >
            <path d="M8 1L13 3.5V7C13 10.5 10.5 13.5 8 14.5C5.5 13.5 3 10.5 3 7V3.5L8 1Z" />
          </svg>

          <span
            style={{
              fontSize: 11,
              fontWeight: 600,
              color: '#a78bfa',
            }}
          >
            Privacy-Preserving
          </span>
        </div>

        <p
          style={{
            fontSize: 10,
            color: '#64748b',
            lineHeight: 1.5,
            margin: 0,
          }}
        >
          Repository contents are processed temporarily and automatically
          deleted after assessment. Source code is not permanently stored.
        </p>
      </div>

      <div style={{ marginTop: 12, paddingLeft: 10 }}>
        <span style={{ fontSize: 10, color: '#334155' }}>
          &copy; 2026 TALGED
        </span>
      </div>
    </aside>
  )
}