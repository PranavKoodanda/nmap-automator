import { useState } from 'react'

function validateTarget(value) {
  const target = value.trim()
  if (!target) return 'Enter an IP address or hostname.'
  if (target.length > 253) return 'The target must be 253 characters or fewer.'

  const ipv6Target = target.startsWith('[') && target.endsWith(']')
    ? target.slice(1, -1)
    : target
  if (ipv6Target.includes(':')) {
    try {
      new URL(`http://[${ipv6Target}]/`)
      return ''
    } catch {
      return 'Enter a valid IPv6 address.'
    }
  }

  if (/^[\d.]+$/.test(target)) {
    const octets = target.split('.')
    if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) {
      return 'Enter a valid IPv4 address, such as 192.0.2.10.'
    }
    return ''
  }

  const labels = target.replace(/\.$/, '').split('.')
  const validHostname = labels.every(
    (label) => label.length > 0 && label.length <= 63 &&
      /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label),
  )
  return validHostname ? '' : 'Enter a valid hostname using letters, numbers, and hyphens.'
}

function StartScan({ profiles, activeScan, error, onStartScan }) {
  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState(profiles[0]?.id ?? '')
  const [validationError, setValidationError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    const targetError = validateTarget(target)
    if (targetError || !profile) {
      setValidationError(targetError || 'Select an approved scan profile.')
      return
    }

    setValidationError('')
    setSubmitting(true)
    try {
      await onStartScan(target.trim(), profile)
    } catch {
      // The parent exposes the service error in the form.
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <>
      <section className="page-heading" aria-labelledby="page-title">
        <div>
          <p className="eyebrow">DEMO WORKFLOW</p>
          <h1 id="page-title">Start a scan</h1>
          <p className="page-description">Configure a simulated scan against a sample target.</p>
        </div>
        <span className="environment-label">No network traffic is sent</span>
      </section>

      <div className="scan-layout">
        <form className="form-panel" onSubmit={handleSubmit} noValidate>
          <div className="panel-heading">
            <p className="eyebrow">CONFIGURATION</p>
            <h2>Scan parameters</h2>
          </div>
          <label className="field-label" htmlFor="scan-target">Target IP or hostname</label>
          <input
            id="scan-target"
            className="text-input"
            type="text"
            autoComplete="off"
            spellCheck="false"
            placeholder="e.g. 192.0.2.10 or demo.example.test"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            aria-invalid={Boolean(validationError)}
            aria-describedby={validationError ? 'target-error' : 'target-help'}
          />
          {validationError ? (
            <p id="target-error" className="field-error" role="alert">{validationError}</p>
          ) : (
            <p id="target-help" className="field-help">Use a target you are authorized to assess. Demo mode never contacts it.</p>
          )}

          <label className="field-label" htmlFor="scan-profile">Approved scan profile</label>
          <select
            id="scan-profile"
            className="text-input select-input"
            value={profile}
            onChange={(event) => setProfile(event.target.value)}
          >
            {profiles.map((item) => (
              <option key={item.id} value={item.id}>{item.label}</option>
            ))}
          </select>
          <p className="field-help profile-help">
            {profiles.find((item) => item.id === profile)?.description}
          </p>

          {error && <div className="alert alert-error" role="alert">{error}</div>}
          <button className="primary-button submit-button" type="submit" disabled={submitting}>
            {submitting ? 'Running simulation…' : 'Start demo scan'}
          </button>
          <p className="form-disclaimer">This development workflow uses fixed sample results. It does not run Nmap.</p>
        </form>

        <aside className="simulation-panel" aria-label="Simulation status">
          <div className="panel-heading">
            <p className="eyebrow">SIMULATION STATUS</p>
            <h2>{statusHeading(activeScan?.status)}</h2>
          </div>
          {activeScan ? (
            <div className="progress-content" role="status" aria-live="polite">
              <div className="progress-labels">
                <span>{activeScan.target}</span>
                <strong>{activeScan.progress}%</strong>
              </div>
              <progress className="scan-progress" value={activeScan.progress} max="100">
                {activeScan.progress}%
              </progress>
              <p>{statusDescription(activeScan.status)}</p>
              {activeScan.status === 'completed' && (
                <p className="success-note">Demo results are ready. They are not live scan output.</p>
              )}
            </div>
          ) : (
            <p className="simulation-note">
              Submit the form to see queued, running, analyzing, and completed states. The sequence is simulated locally.
            </p>
          )}
          <div className="simulation-steps" aria-label="Demo lifecycle">
            {['Queued', 'Running', 'Analyzing', 'Complete'].map((step, index) => (
              <div className="simulation-step" key={step}>
                <span className={activeScan?.progress >= [0, 35, 75, 100][index] ? 'step-dot is-reached' : 'step-dot'} />
                {step}
              </div>
            ))}
          </div>
        </aside>
      </div>
    </>
  )
}

function statusHeading(status) {
  return {
    queued: 'Queued',
    running: 'Simulation running',
    analyzing: 'Analyzing demo data',
    completed: 'Simulation complete',
  }[status] ?? 'Ready to simulate'
}

function statusDescription(status) {
  return {
    queued: 'Preparing the local demonstration.',
    running: 'Playing the simulated discovery step.',
    analyzing: 'Adding fixed demonstration results.',
    completed: 'The demonstration lifecycle finished.',
  }[status] ?? 'Waiting for the simulation.'
}

export default StartScan