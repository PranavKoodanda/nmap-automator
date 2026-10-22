import ScanProgressBar from '../components/ScanProgressBar'

function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(value))
}

function Dashboard({ scans, onOpenActivity, onStopScan, onNavigate, historyOnly = false, demoMode }) {
  const completedScans = scans.filter((scan) => scan.status === 'completed')
  const openPorts = completedScans.reduce(
    (total, scan) => total + scan.ports.filter((port) => port.state === 'open').length,
    0,
  )
  const hostCount = new Set(scans.map((scan) => scan.target)).size
  const findingCount = completedScans.reduce(
    (total, scan) => total + scan.findings.length,
    0,
  )
  const title = historyOnly ? 'Scan history' : 'Dashboard'
  const orderedScans = [...scans].sort(compareScans)
  const rows = historyOnly ? orderedScans : orderedScans.slice(0, 5)

  return (
    <>
      <section className="page-heading" aria-labelledby="page-title">
        <div>
          <p className="eyebrow">SECURITY WORKSPACE</p>
          <h1 id="page-title">{title}</h1>
          <p className="page-description">
            {historyOnly
              ? `Review previous ${demoMode ? 'demonstration' : 'backend'} scans and open their results.`
              : 'A live view of scan activity and reported observations.'}
          </p>
        </div>
        <button className="primary-button" type="button" onClick={() => onNavigate('start-scan')}>
          <span aria-hidden="true">+</span> Start scan
        </button>
      </section>

      {!historyOnly && (
        <section className="metrics-grid" aria-label="Scan summary">
          <Metric label="Total scans" value={scans.length} note={demoMode ? 'Demo records' : 'Browser-tracked IDs'} marker="SC" />
          <Metric label="Open ports" value={openPorts} note="Across completed scans" marker="PT" />
          <Metric label="Hosts" value={hostCount} note={demoMode ? 'Unique demo targets' : 'Unique backend targets'} marker="HS" />
          <Metric label="Potential findings" value={findingCount} note={demoMode ? 'Informational demo items' : 'Backend rule findings'} marker="FN" />
        </section>
      )}

      {historyOnly && (
        <ActiveScans scans={orderedScans} onOpenActivity={onOpenActivity} onStopScan={onStopScan} demoMode={demoMode} />
      )}

      <section className="content-section" aria-labelledby="scan-list-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">{demoMode ? 'DEMONSTRATION DATA' : 'BACKEND SCAN DATA'}</p>
            <h2 id="scan-list-title">{historyOnly ? 'All scans' : 'Recent scans'}</h2>
          </div>
          {!historyOnly && scans.length > 5 && (
            <button className="text-button" type="button" onClick={() => onNavigate('history')}>
              View history
            </button>
          )}
        </div>

        {rows.length === 0 ? (
          <div className="empty-list">
            <strong>No scans yet</strong>
            <p>{demoMode ? 'Start a demonstration scan to see activity here. No real network scan will run.' : 'Start an authorized backend scan to see activity here.'}</p>
            <button className="secondary-button" type="button" onClick={() => onNavigate('start-scan')}>
              {demoMode ? 'Configure a demo scan' : 'Start a backend scan'}
            </button>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Target</th>
                  <th scope="col">Profile</th>
                  <th scope="col">Status</th>
                  <th scope="col">Started</th>
                  <th scope="col"><span className="visually-hidden">Action</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((scan) => (
                  <tr key={scan.id}>
                    <td data-label="Target">
                      <span className="target-value">{scan.target}</span>
                      {demoMode && <span className="row-demo-tag">DEMO</span>}
                    </td>
                    <td data-label="Profile" className="capitalize">{scan.profile.replaceAll('_', ' ').replaceAll('-', ' ')}</td>
                    <td data-label="Status">
                      <span className={`status-label status-${scan.status}`}>
                        <span />{scan.status}
                      </span>
                      {scan.status === 'queued' && (
                        <div className="muted-cell">Waiting for an available worker.</div>
                      )}
                      {scan.status === 'running' && scan.progress && (
                        <div className="scan-row-progress">
                          <ScanProgressBar percent={scan.progress.percent} status={scan.status} />
                          <div className="muted-cell">
                            {scan.progress.stage ? `${scan.progress.stage} · ` : ''}
                            {scan.progress.percent != null ? `${scan.progress.percent}%` : 'Scanning — progress percentage unavailable'}
                            {` · ${formatElapsed(scan.progress.elapsed_seconds)}`}
                          </div>
                        </div>
                      )}
                      {scan.status === 'failed' && scan.error && (
                        <div className="field-error">{scan.error}</div>
                      )}
                    </td>
                    <td data-label="Started" className="muted-cell">{formatDate(scan.startedAt)}</td>
                    <td className="action-cell">
                      <button
                        className="text-button"
                        type="button"
                        onClick={() => onOpenActivity(scan)}
                      >
                        View terminal <span aria-hidden="true">→</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {!historyOnly && (
        <p className="data-disclaimer">
          {demoMode ? 'Demo mode is active. Counts and scan results are sample data, not findings from a real network.' : 'Real scan IDs are tracked in this browser; backend records disappear when the server restarts.'}
        </p>
      )}
    </>
  )
}

function ActiveScans({ scans, onOpenActivity, onStopScan, demoMode }) {
  const activeScans = scans.filter(
    (scan) => scan.status === 'queued' || scan.status === 'running',
  )
  return (
    <section className="content-section active-scans-section" aria-labelledby="active-scans-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">LIVE MONITORING</p>
          <h2 id="active-scans-title">Active scans</h2>
        </div>
        <span className="muted-cell">{activeScans.length} active</span>
      </div>
      {activeScans.length === 0 ? (
        <p className="empty-list">No queued or running scans.</p>
      ) : (
        <div className="active-scan-grid">
          {activeScans.map((scan) => (
            <article
              className="active-scan-card"
              key={scan.id}
            >
              <span className="active-scan-card-top">
                <strong>{scan.target}</strong>
                <span className={`status-label status-${scan.status}`}><span />{scan.status}</span>
              </span>
              <span className="capitalize">{scan.profile.replaceAll('_', ' ')}</span>
              <span className="active-scan-stage">
                {scan.progress?.stage || (scan.status === 'queued'
                  ? 'Waiting for worker'
                  : scan.progress?.message || 'Waiting for Nmap output')}
              </span>
              <span className="active-scan-meta">
                {scan.progress?.percent != null ? `${scan.progress.percent}%` : 'Indeterminate'}
                {' · '}
                {formatElapsed(scan.progress?.elapsed_seconds)}
              </span>
              <span className="active-scan-message">
                {staleOutputLabel(scan) || scan.events?.at(-1)?.message || scan.progress?.message || 'Waiting for activity.'}
              </span>
              <div className="active-scan-actions">
                <button className="text-button" type="button" onClick={() => onOpenActivity(scan)}>View terminal</button>
                {!demoMode && <button className="danger-button danger-button-small" type="button" onClick={() => onStopScan(scan.id)}>Stop scan</button>}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  )
}

function compareScans(left, right) {
  const leftTime = Date.parse(left.startedAt || left.createdAt || '') || 0
  const rightTime = Date.parse(right.startedAt || right.createdAt || '') || 0
  if (rightTime !== leftTime) return rightTime - leftTime
  return String(right.id).localeCompare(String(left.id))
}

function formatElapsed(seconds) {
  if (!Number.isFinite(seconds)) return 'time unavailable'
  const total = Math.max(0, Math.round(seconds))
  const minutes = Math.floor(total / 60)
  return minutes ? `${minutes}m ${total % 60}s` : `${total}s`
}

function staleOutputLabel(scan) {
  if (scan.status !== 'running') return ''
  const lastOutput = [...(scan.events || [])].reverse().find((event) => (
    event.message !== 'Nmap scan started.' &&
    !event.message.toLowerCase().includes('waiting for output') &&
    !event.message.toLowerCase().includes('no new nmap output')
  ))
  const timestamp = lastOutput?.timestamp || scan.startedAt
  const time = Date.parse(timestamp || '')
  if (!Number.isFinite(time) || Date.now() - time < 15000) return ''
  return `No new Nmap output; last activity at ${new Date(time).toLocaleTimeString()}.`
}

function Metric({ label, value, note, marker }) {
  return (
    <article className="metric-card">
      <div className="metric-topline">
        <span>{label}</span>
        <span className="metric-marker" aria-hidden="true">{marker}</span>
      </div>
      <strong className="metric-value">{value}</strong>
      <span className="metric-note">{note}</span>
    </article>
  )
}

export default Dashboard
