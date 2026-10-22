import { useEffect, useRef } from 'react'
import ScanProgressBar from '../components/ScanProgressBar'

function ScanActivityView({ scan, onBack }) {
  const logRef = useRef(null)
  const wasAtBottomRef = useRef(true)

  useEffect(() => {
    const log = logRef.current
    if (!log || !wasAtBottomRef.current) return
    log.scrollTop = log.scrollHeight
  }, [scan?.events?.length])

  function trackScroll(event) {
    const element = event.currentTarget
    wasAtBottomRef.current =
      element.scrollHeight - element.scrollTop - element.clientHeight < 24
  }

  const staleMessage = getStaleOutputMessage(scan)

  if (!scan) {
    return (
      <section className="state-panel" role="alert">
        <p>This scan is no longer available.</p>
        <button className="secondary-button" type="button" onClick={onBack}>Back to history</button>
      </section>
    )
  }

  return (
    <>
      <section className="page-heading">
        <div>
          <p className="eyebrow">LIVE SCAN ACTIVITY</p>
          <h1>{scan.target}</h1>
          <p className="page-description">
            {scan.profile.replaceAll('_', ' ')} · {scan.status}
          </p>
        </div>
        <button className="secondary-button" type="button" onClick={onBack}>Back to history</button>
      </section>
      <section className="activity-view-panel" aria-label="Scan activity">
        <div className="activity-view-summary">
          <span className={`status-label status-${scan.status}`}><span />{scan.status}</span>
          <span>{scan.progress?.stage || scan.progress?.message || 'Waiting for Nmap output'}</span>
          <span>{scan.progress?.percent != null ? `${scan.progress.percent}%` : 'Indeterminate'}</span>
          <span>{formatElapsed(scan.progress?.elapsed_seconds)}</span>
        </div>
        {staleMessage && <p className="muted-cell" role="status">{staleMessage}</p>}
        {scan.status === 'running' && (
          <ScanProgressBar percent={scan.progress?.percent} status={scan.status} />
        )}
        {scan.error && <p className="field-error">{scan.error}</p>}
        <ol className="terminal-log" ref={logRef} onScroll={trackScroll}>
          {scan.events?.length ? scan.events.map((event) => (
            <li className={`activity-${event.eventType}`} key={event.sequence}>
              <time dateTime={event.timestamp}>
                {new Date(event.timestamp).toLocaleTimeString()}
              </time>
              <strong>{event.eventType.replaceAll('_', ' ')}</strong>
              <span>{event.message}</span>
            </li>
          )) : (
            <li className="terminal-log-empty">Waiting for scan activity.</li>
          )}
        </ol>
      </section>
    </>
  )
}

function getStaleOutputMessage(scan) {
  if (!scan || scan.status !== 'running') return ''
  const lastOutput = [...(scan.events || [])].reverse().find((event) => (
    event.message !== 'Nmap scan started.' &&
    !event.message.toLowerCase().includes('waiting for output') &&
    !event.message.toLowerCase().includes('no new nmap output')
  ))
  const timestamp = lastOutput?.timestamp || scan.startedAt
  const time = Date.parse(timestamp || '')
  if (!Number.isFinite(time) || Date.now() - time < 15000) return ''
  return `No new Nmap output; last activity was received at ${new Date(time).toLocaleTimeString()}.`
}

function formatElapsed(seconds) {
  if (!Number.isFinite(seconds)) return 'time unavailable'
  const total = Math.max(0, Math.round(seconds))
  const minutes = Math.floor(total / 60)
  return minutes ? `${minutes}m ${total % 60}s` : `${total}s`
}

export default ScanActivityView
