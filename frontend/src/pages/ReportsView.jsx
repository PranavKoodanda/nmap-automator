import { useState } from 'react'
import { downloadReport } from '../services/scanService'

function profileName(profile) {
  return profile.replaceAll('_', ' ').replaceAll('-', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function ReportsView({ scans, onOpenScan, demoMode }) {
  const reportableScans = scans.filter((scan) => ['completed', 'cancelled'].includes(scan.status))
  const [scanId, setScanId] = useState('')
  const [downloadError, setDownloadError] = useState('')
  const [downloaded, setDownloaded] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [format, setFormat] = useState(demoMode ? 'pdf' : 'html')
  const scan = reportableScans.find((item) => item.id === scanId) ?? reportableScans[0] ?? null

  async function handleDownloadClick() {
    setDownloaded(false)
    setDownloadError('')
    setGenerating(true)
    try {
      await downloadReport(scan, format)
      setDownloaded(true)
    } catch {
      setDownloadError(demoMode ? 'The demonstration PDF could not be created.' : `The backend ${format.toUpperCase()} report could not be downloaded.`)
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
          <p className="page-description">{demoMode ? 'Preview and download a PDF demonstration report.' : 'Download detailed reports for completed scans and incomplete cancelled scans.'}</p>
        </div>
        <span className="demo-badge demo-badge-light">{demoMode ? 'DEMONSTRATION ONLY' : 'BACKEND REPORT'}</span>
      </section>

      <section className="report-controls content-section" aria-label="Report selection">
        <div>
          <label className="field-label" htmlFor="report-scan">Reportable {demoMode ? 'demonstration' : 'backend'} scan</label>
          <select id="report-scan" className="text-input report-select" value={scan?.id ?? ''} onChange={(event) => { setScanId(event.target.value); setDownloaded(false) }} disabled={reportableScans.length === 0}>
            {reportableScans.length === 0 ? <option value="">No reportable scans</option> : reportableScans.map((item) => (
              <option key={item.id} value={item.id}>{item.target} - {profileName(item.profile)} - {new Date(item.startedAt).toLocaleString()}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="field-label" htmlFor="report-format">Export format</label>
          <select id="report-format" className="text-input report-select" value={format} onChange={(event) => { setFormat(event.target.value); setDownloaded(false) }} disabled={generating}>
            {demoMode ? <option value="pdf">PDF (demonstration)</option> : <>
              <option value="html">HTML</option>
              <option value="json">JSON</option>
              <option value="pdf">PDF</option>
            </>}
          </select>
        </div>
        <button className="primary-button download-link" type="button" onClick={handleDownloadClick} disabled={!scan || generating}>
          {generating ? 'Preparing report…' : (demoMode ? 'Download demo PDF' : `Download ${format.toUpperCase()} report`)}
        </button>
      </section>

      {downloadError && <p className="field-error" role="alert">{downloadError}</p>}
      {downloaded && <p className="success-note" role="status">
        {demoMode ? 'The demonstration PDF was generated and the download was requested.' : `The backend ${format.toUpperCase()} report download was requested.`}
      </p>}
      {!scan ? (
        <div className="empty-list"><strong>No report available</strong><p>Complete or cancel a {demoMode ? 'simulated' : 'backend'} scan before downloading a report.</p></div>
      ) : (
        <article className="report-preview" aria-labelledby="report-title">
          <div className="report-preview-header">
            <div><p className="eyebrow">NMAP AUTOMATOR · {demoMode ? 'PDF PREVIEW' : 'HTML REPORT'}</p><h2 id="report-title">Security assessment</h2></div>
            {demoMode && <span className="row-demo-tag">SAMPLE</span>}
          </div>
          <dl className="report-metadata">
            <div><dt>Target</dt><dd>{scan.target}</dd></div>
            <div><dt>Status</dt><dd>{scan.status}</dd></div>
            <div><dt>Scan profile</dt><dd>{scan.profile.replaceAll('_', ' ').replaceAll('-', ' ')}</dd></div>
            <div><dt>{scan.status === 'cancelled' ? 'Stopped' : 'Completed'}</dt><dd>{scan.completedAt ? new Date(scan.completedAt).toLocaleString() : 'Unavailable'}</dd></div>
            <div><dt>{demoMode ? 'Ports in sample' : 'Reported ports'}</dt><dd>{scan.ports.length}</dd></div>
            <div><dt>Open ports</dt><dd>{scan.ports.filter((port) => port.state === 'open').length}</dd></div>
            <div><dt>{demoMode ? 'Observations' : 'Findings'}</dt><dd>{scan.findings.length}</dd></div>
          </dl>
          {scan.status === 'cancelled' && <p className="alert alert-error" role="note">Incomplete scan. Only captured observations are included; unscanned ports and services remain unknown.</p>}
          <p className="report-disclaimer">{demoMode ? 'Demonstration data only. No network traffic was sent and no vulnerability assessment was performed.' : (scan.status === 'cancelled' ? 'The report includes captured ports, rule-based observations, and retained Nmap output. Missing items were not assessed.' : 'Report content is generated by the backend from the completed scan record.')}</p>
          <button className="text-button" type="button" onClick={() => onOpenScan(scan)}>View associated results <span aria-hidden="true">→</span></button>
        </article>
      )}
    </>
  )
}

export default ReportsView
