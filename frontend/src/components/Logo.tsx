export default function Logo() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <div
        style={{
          width: 32,
          height: 32,
          borderRadius: 8,
          background: 'linear-gradient(135deg, #7c3aed, #3b82f6)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
          <path
            d="M8 1L13 4V8C13 11.31 10.84 14.4 8 15C5.16 14.4 3 11.31 3 8V4L8 1Z"
            fill="white"
            fillOpacity="0.9"
          />
          <path
            d="M6 8L7.5 9.5L10 7"
            stroke="#3b82f6"
            strokeWidth="1.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>

      <span
        style={{
          fontWeight: 700,
          fontSize: 16,
          color: '#e2e8f0',
          letterSpacing: '-0.01em',
        }}
      >
        Ligtask
      </span>
    </div>
  )
}