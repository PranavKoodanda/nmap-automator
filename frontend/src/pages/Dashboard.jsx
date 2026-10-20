function formatDate(value) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(value))
}

function Dashboard({ scans, onOpenScan, onNavigate, historyOnly = false }) {
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
  const rows = historyOnly ? scans : scans.slice(0, 5)

  return (
    <>
      <section className="page-heading" aria-labelledby="page-title">
        <div>
          <p className="eyebrow">SECURITY WORKSPACE</p>
          <h1 id="page-title">{title}</h1>
          <p className="page-description">
            {historyOnly
              ? 'Review previous demonstration scans and open their results.'
              : 'A live view of scan activity and reported observations.'}
          </p>
        </div>
        <button className="primary-button" type="button" onClick={() => onNavigate('start-scan')}>
          <span aria-hidden="true">+</span> Start scan
        </button>
      </section>

      {!historyOnly && (
        <section className="metrics-grid" aria-label="Demonstration scan summary">
          <Metric label="Total scans" value={scans.length} note="Demo records" marker="SC" />
          <Metric label="Open ports" value={openPorts} note="Across completed scans" marker="PT" />
          <Metric label="Hosts" value={hostCount} note="Unique demo targets" marker="HS" />
          <Metric label="Potential findings" value={findingCount} note="Informational demo items" marker="FN" />
        </section>
      )}

      <section className="content-section" aria-labelledby="scan-list-title">
        <div className="section-heading">
          <div>
            <p className="eyebrow">DEMONSTRATION DATA</p>
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
            <p>Start a demonstration scan to see activity here. No real network scan will run.</p>
            <button className="secondary-button" type="button" onClick={() => onNavigate('start-scan')}>
              Configure a demo scan
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
                      <span className="row-demo-tag">DEMO</span>
                    </td>
                    <td data-label="Profile" className="capitalize">{scan.profile.replaceAll('-', ' ')}</td>
                    <td data-label="Status">
                      <span className={`status-label status-${scan.status}`}>
                        <span />{scan.status}
                      </span>
                    </td>
                    <td data-label="Started" className="muted-cell">{formatDate(scan.startedAt)}</td>
                    <td className="action-cell">
                      <button
                        className="text-button"
                        type="button"
                        onClick={() => onOpenScan(scan)}
                        disabled={scan.status !== 'completed'}
                      >
                        View results <span aria-hidden="true">→</span>
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
          Demo mode is active. Counts and scan results are sample data, not findings from a real network.
        </p>
      )}
    </>
  )
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