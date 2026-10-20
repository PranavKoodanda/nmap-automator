import { useMemo, useState } from 'react'

function ResultsView({ scan, onNavigate }) {
  const [query, setQuery] = useState('')
  const [stateFilter, setStateFilter] = useState('all')
  const [sortOrder, setSortOrder] = useState('port-asc')

  const ports = useMemo(() => {
    if (!scan) return []
    const normalizedQuery = query.trim().toLowerCase()
    return scan.ports
      .filter((port) => stateFilter === 'all' || port.state === stateFilter)
      .filter((port) => [port.port, port.protocol, port.service, port.product, port.version]
        .some((value) => String(value ?? '').toLowerCase().includes(normalizedQuery)))
      .sort((left, right) => sortOrder === 'port-desc'
        ? right.port - left.port
        : left.port - right.port)
  }, [query, scan, sortOrder, stateFilter])

  if (!scan) {
    return (
      <section className="page-heading">
        <div>
          <p className="eyebrow">SCAN RESULTS</p>
          <h1>Results unavailable</h1>
          <p className="page-description">This scan may have been removed from local demo history.</p>
        </div>
        <button className="secondary-button" type="button" onClick={() => onNavigate('history')}>
          Open scan history
        </button>
      </section>
    )
  }

  return (
    <>
      <section className="page-heading" aria-labelledby="page-title">
        <div>
          <p className="eyebrow">DEMONSTRATION RESULTS</p>
          <h1 id="page-title">Scan results</h1>
          <p className="page-description">Target <strong>{scan.target}</strong> · {scan.profile.replaceAll('-', ' ')}</p>
        </div>
        <span className="demo-badge demo-badge-light">SAMPLE DATA · NOT A REAL SCAN</span>
      </section>

      <section className="result-summary" aria-label="Scan summary">
        <div><span>Scan status</span><strong className="status-label status-completed"><span />{scan.status}</strong></div>
        <div><span>Ports in sample</span><strong>{scan.ports.length}</strong></div>
        <div><span>Open ports</span><strong>{scan.ports.filter((port) => port.state === 'open').length}</strong></div>
        <div><span>Observations</span><strong>{scan.findings.length}</strong></div>
      </section>

      <section className="content-section" aria-labelledby="ports-title">
        <div className="section-heading result-heading">
          <div>
            <p className="eyebrow">PORT AND SERVICE INVENTORY</p>
            <h2 id="ports-title">Port results</h2>
          </div>
          <div className="table-controls">
            <label className="visually-hidden" htmlFor="port-search">Search port results</label>
            <input id="port-search" className="compact-input" type="search" placeholder="Search ports or services" value={query} onChange={(event) => setQuery(event.target.value)} />
            <label className="visually-hidden" htmlFor="state-filter">Filter by port state</label>
            <select id="state-filter" className="compact-input" value={stateFilter} onChange={(event) => setStateFilter(event.target.value)}>
              <option value="all">All states</option>
              <option value="open">Open</option>
              <option value="closed">Closed</option>
              <option value="filtered">Filtered</option>
            </select>
            <label className="visually-hidden" htmlFor="port-sort">Sort port results</label>
            <select id="port-sort" className="compact-input sort-input" value={sortOrder} onChange={(event) => setSortOrder(event.target.value)}>
              <option value="port-asc">Port: low to high</option>
              <option value="port-desc">Port: high to low</option>
            </select>
          </div>
        </div>
        {ports.length === 0 ? (
          <div className="empty-list"><strong>No matching ports</strong><p>Change the search or state filter.</p></div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th scope="col">Port</th><th scope="col">Protocol</th><th scope="col">State</th><th scope="col">Service</th><th scope="col">Product</th><th scope="col">Version</th></tr></thead>
              <tbody>
                {ports.map((port) => (
                  <tr key={`${port.port}/${port.protocol}`}>
                    <td data-label="Port" className="port-number">{port.port}</td>
                    <td data-label="Protocol">{port.protocol.toUpperCase()}</td>
                    <td data-label="State"><span className={`status-label status-${port.state}`}><span />{port.state}</span></td>
                    <td data-label="Service">{port.service || <span className="unavailable">Unavailable</span>}</td>
                    <td data-label="Product">{port.product || <span className="unavailable">Unavailable</span>}</td>
                    <td data-label="Version">{port.version || <span className="unavailable">Unavailable</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="content-section findings-section" aria-labelledby="findings-title">
        <div className="section-heading">
          <div><p className="eyebrow">BACKEND-STYLE OBSERVATIONS</p><h2 id="findings-title">Potential findings</h2></div>
        </div>
        {scan.findings.length === 0 ? (
          <div className="empty-list"><strong>No demonstration findings</strong><p>This is not a security guarantee; no real analysis was performed.</p></div>
        ) : scan.findings.map((finding) => (
          <article className="finding-row" key={finding.id}>
            <span className="severity-tag">{finding.severity}</span>
            <div><strong>{finding.title}</strong><p>{finding.description}</p></div>
          </article>
        ))}
      </section>
    </>
  )
}

export default ResultsView