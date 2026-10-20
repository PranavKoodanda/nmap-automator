const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', marker: '01' },
  { id: 'start-scan', label: 'Start scan', marker: '02' },
  { id: 'history', label: 'Scan history', marker: '03' },
  { id: 'reports', label: 'Reports', marker: '04' },
]

function AppLayout({ page, onNavigate, demoMode, children }) {
  return (
    <div className="app-shell">
      <header className="topbar">
        <button className="brand" type="button" onClick={() => onNavigate('dashboard')}>
          <span className="brand-mark" aria-hidden="true">N</span>
          <span>Nmap <strong>Automator</strong></span>
        </button>
        <div className="topbar-state">
          <span className="demo-badge">DEMO MODE</span>
          <span className="connection-status">
            <span className="status-dot" aria-hidden="true" />
            API not connected
          </span>
        </div>
      </header>

      <div className="app-frame">
        <aside className="sidebar" aria-label="Main navigation">
          <p className="sidebar-label">WORKSPACE</p>
          <nav className="main-nav">
            {NAV_ITEMS.map((item) => (
              <button
                className={`nav-item${page === item.id ? ' is-active' : ''}`}
                type="button"
                key={item.id}
                aria-current={page === item.id ? 'page' : undefined}
                onClick={() => onNavigate(item.id)}
              >
                <span className="nav-marker" aria-hidden="true">{item.marker}</span>
                {item.label}
              </button>
            ))}
          </nav>
          <div className="sidebar-note">
            <span className="sidebar-note-dot" aria-hidden="true" />
            {demoMode ? 'Local demonstration data' : 'Backend connected'}
          </div>
        </aside>
        <main className="main-content">{children}</main>
      </div>
    </div>
  )
}

export default AppLayout