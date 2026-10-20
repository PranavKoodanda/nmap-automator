import { useState } from 'react'
import { downloadDemoReportPdf } from '../services/pdfReport'

function ReportsView({ scans, onOpenScan }) {
  const completedScans = scans.filter((scan) => scan.status === 'completed')
  const [scanId, setScanId] = useState('')
  const [downloadError, setDownloadError] = useState('')
  const [downloaded, setDownloaded] = useState(false)
  const [generating, setGenerating] = useState(false)
  const scan = completedScans.find((item) => item.id === scanId) ?? completedScans[0] ?? null

  async function handleDownloadClick() {
    setDownloaded(false)
    setDownloadError('')
    setGenerating(true)
    try {
      await downloadDemoReportPdf(scan)
      setDownloaded(true)
    } catch {
      setDownloadError('The demonstration PDF could not be created.')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <>
      <section className="page-heading" aria-labelledby="page-title">
        <div>
          <p className="eyebrow">REPORTS</p>
          <h1 id="page-title">Assessment report</h1>
          <p className="page-description">Preview and download a PDF demonstration report.</p>
        </div>
        <span className="demo-badge demo-badge-light">DEMONSTRATION ONLY</span>
      </section>

      <section className="report-controls content-section" aria-label="Report selection">
        <div>
          <label className="field-label" htmlFor="report-scan">Completed demonstration scan</label>
          <select id="report-scan" className="text-input report-select" value={scan?.id ?? ''} onChange={(event) => { setScanId(event.target.value); setDownloaded(false) }} disabled={completedScans.length === 0}>
            {completedScans.length === 0 ? <option value="">No completed scans</option> : completedScans.map((item) => (
              <option key={item.id} value={item.id}>{item.target} · {new Date(item.startedAt).toLocaleString()}</option>
            ))}
          </select>
        </div>
        <button className="primary-button download-link" type="button" onClick={handleDownloadClick} disabled={!scan || generating}>
          {generating ? 'Preparing PDF…' : 'Download demo PDF'}
        </button>
      </section>

      {downloadError && <p className="field-error" role="alert">{downloadError}</p>}
      {downloaded && <p className="success-note" role="status">The demonstration PDF was generated and the download was requested.</p>}
      {!scan ? (
        <div className="empty-list"><strong>No report available</strong><p>Complete a simulated scan before previewing a report.</p></div>
      ) : (
        <article className="report-preview" aria-labelledby="report-title">
          <div className="report-preview-header">
            <div><p className="eyebrow">NMAP AUTOMATOR · PDF PREVIEW</p><h2 id="report-title">Security assessment</h2></div>
            <span className="row-demo-tag">SAMPLE</span>
          </div>
          <dl className="report-metadata">
            <div><dt>Target</dt><dd>{scan.target}</dd></div>
            <div><dt>Scan profile</dt><dd>{scan.profile.replaceAll('-', ' ')}</dd></div>
            <div><dt>Completed</dt><dd>{scan.completedAt ? new Date(scan.completedAt).toLocaleString() : 'Unavailable'}</dd></div>
            <div><dt>Ports in sample</dt><dd>{scan.ports.length}</dd></div>
            <div><dt>Open ports</dt><dd>{scan.ports.filter((port) => port.state === 'open').length}</dd></div>
            <div><dt>Observations</dt><dd>{scan.findings.length}</dd></div>
          </dl>
          <p className="report-disclaimer">Demonstration data only. No network traffic was sent and no vulnerability assessment was performed.</p>
          <button className="text-button" type="button" onClick={() => onOpenScan(scan)}>View associated results <span aria-hidden="true">→</span></button>
        </article>
      )}
    </>
  )
}

export default ReportsView