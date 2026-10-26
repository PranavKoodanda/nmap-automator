import { useState } from 'react'
import ScanProgressBar from '../components/ScanProgressBar'
import { createDomainChallenge, verifyDomainChallenge } from '../services/scanService'

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

function validateFqdn(value) {
  const syntaxError = validateTarget(value)
  if (syntaxError) return syntaxError
  const hostname = value.trim().replace(/\.$/, '')
  if (hostname.includes(':') || /^[\d.]+$/.test(hostname)) {
    return 'Public scans require a fully qualified domain name, not an IP address.'
  }
  if (!hostname.includes('.')) return 'Enter a fully qualified domain name, such as example.com.'
  return ''
}

function StartScan({ profiles, activeScan, error, onStartScan, verifiedHost, onVerified, demoMode }) {
  const [target, setTarget] = useState('')
  const [profile, setProfile] = useState(profiles[0]?.id ?? '')
  const [validationError, setValidationError] = useState('')
  const [verificationError, setVerificationError] = useState('')
  const [domain, setDomain] = useState('')
  const [challenge, setChallenge] = useState(null)
  const [verificationBusy, setVerificationBusy] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const needsVerification = !demoMode && !verifiedHost

  async function handleCreateChallenge(event) {
    event.preventDefault()
    const errorMessage = validateFqdn(domain)
    if (errorMessage) {
      setVerificationError(errorMessage)
      return
    }
    setVerificationBusy(true)
    setVerificationError('')
    try {
      setChallenge(await createDomainChallenge(domain.trim()))
    } catch (error) {
      setVerificationError(error.message)
    } finally {
      setVerificationBusy(false)
    }
  }

  async function handleVerifyChallenge() {
    if (!challenge) return
    setVerificationBusy(true)
    setVerificationError('')
    try {
      const hostname = await verifyDomainChallenge(challenge.challenge_id)
      setChallenge(null)
      setDomain('')
      onVerified(hostname)
    } catch (error) {
      setVerificationError(error.message)
    } finally {
      setVerificationBusy(false)
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()
    const scanTarget = demoMode ? target : verifiedHost
    const targetError = demoMode ? validateTarget(target) : validateFqdn(scanTarget)
    if (targetError || !profile) {
      setValidationError(targetError || 'Select an approved scan profile.')
      return
    }

    setValidationError('')
    setSubmitting(true)
    try {
      await onStartScan(scanTarget.trim(), profile, () => setSubmitting(false))
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
          <p className="eyebrow">{demoMode ? 'DEMO WORKFLOW' : 'LIVE API WORKFLOW'}</p>
          <h1 id="page-title">Start a scan</h1>
          <p className="page-description">{demoMode ? 'Configure a simulated scan against a sample target.' : 'Start an authorized scan through the backend.'}</p>
        </div>
        <span className="environment-label">{demoMode ? 'No network traffic is sent' : 'Backend scan enabled'}</span>
      </section>

      <div className="scan-layout">
        <form className="form-panel" onSubmit={needsVerification ? handleCreateChallenge : handleSubmit} noValidate>
          {needsVerification ? (
            <>
              <div className="panel-heading">
                <p className="eyebrow">DOMAIN OWNERSHIP</p>
                <h2>Verify a hostname</h2>
              </div>
              <p className="field-help">To enable scanning, publish the TXT record below on a fully qualified domain name you control. Only that hostname can be scanned.</p>
              <label className="field-label" htmlFor="verification-domain">Domain name</label>
              <input
                id="verification-domain"
                className="text-input"
                type="text"
                autoComplete="url"
                spellCheck="false"
                placeholder="example.com"
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                disabled={verificationBusy}
              />
              {challenge && (
                <div className="verification-record" aria-live="polite">
                  <p>Add this DNS TXT record. DNS propagation may take a few minutes.</p>
                  <dl>
                    <dt>Record name</dt><dd><code>{challenge.record_name}</code></dd>
                    <dt>TXT value</dt><dd><code>{challenge.txt_value}</code></dd>
                    <dt>Challenge expires</dt><dd>{new Date(challenge.expires_at).toLocaleString()}</dd>
                  </dl>
                  <button className="primary-button" type="button" onClick={handleVerifyChallenge} disabled={verificationBusy}>
                    {verificationBusy ? 'Checking DNS…' : 'Verify DNS record'}
                  </button>
                </div>
              )}
              {verificationError && <div className="alert alert-error" role="alert">{verificationError}</div>}
              {!challenge && (
                <button className="primary-button submit-button" type="submit" disabled={verificationBusy}>
                  {verificationBusy ? 'Creating challenge…' : 'Create DNS challenge'}
                </button>
              )}
              <p className="form-disclaimer">Challenges expire and are stored temporarily in backend memory. DNS ownership verification is required before scans are enabled.</p>
            </>
          ) : (
          <>
          <div className="panel-heading">
            <p className="eyebrow">CONFIGURATION</p>
            <h2>{demoMode ? 'Scan parameters' : 'Verified scan target'}</h2>
          </div>
          {!demoMode && (
            <button className="text-button" type="button" onClick={() => onVerified('')}>
              Verify a different hostname
            </button>
          )}
          <label className="field-label" htmlFor="scan-target">{demoMode ? 'Target IP or hostname' : 'Verified hostname'}</label>
          <input
            id="scan-target"
            className="text-input"
            type="text"
            autoComplete="off"
            spellCheck="false"
            placeholder={demoMode ? 'e.g. 192.0.2.10 or demo.example.test' : 'Verified domain'}
            value={demoMode ? target : verifiedHost}
            disabled={!demoMode}
            onChange={(event) => setTarget(event.target.value)}
            aria-invalid={Boolean(validationError)}
            aria-describedby={validationError ? 'target-error' : 'target-help'}
          />
          {validationError ? (
            <p id="target-error" className="field-error" role="alert">{validationError}</p>
          ) : (
            <p id="target-help" className="field-help">{demoMode ? 'Demo mode never contacts this target.' : 'Ownership is verified by DNS TXT record. The backend will scan one validated public address for this hostname.'}</p>
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
          {['full_tcp', 'comprehensive_tcp', 'udp_top_100', 'tcp_udp_common'].includes(profile) && (
            <p className="field-help">This profile can take considerably longer than a basic scan.</p>
          )}

          {error && <div className="alert alert-error" role="alert">{error}</div>}
          <button className="primary-button submit-button" type="submit" disabled={submitting}>
            {submitting ? (demoMode ? 'Running simulation…' : 'Submitting scan…') : (demoMode ? 'Start demo scan' : 'Start scan')}
          </button>
          <p className="form-disclaimer">{demoMode ? 'This development workflow uses fixed sample results. It does not run Nmap.' : 'The backend uses fixed scan profiles, public-address checks, and bounded scan capacity.'}</p>
          </>
          )}
        </form>

        <aside className="simulation-panel" aria-label="Simulation status">
          <div className="panel-heading">
            <p className="eyebrow">{demoMode ? 'SIMULATION STATUS' : 'SCAN STATUS'}</p>
            <h2>{demoMode ? statusHeading(activeScan?.status) : (activeScan ? activeScan.status : 'Ready to scan')}</h2>
          </div>
          {activeScan ? (
            <div className="progress-content" role="status" aria-live="polite">
              <div className="progress-labels">
                <span>{activeScan.target}</span>
                {!demoMode && activeScan.progress?.percent != null && (
                  <strong>{activeScan.progress.percent}%</strong>
                )}
                {demoMode && <strong>{activeScan.progress}%</strong>}
              </div>
              {activeScan.status !== 'queued' && (demoMode
                ? <ScanProgressBar percent={activeScan.progress} status={activeScan.status} />
                : <ScanProgressBar percent={activeScan.progress?.percent} status={activeScan.status} />)}
              {!demoMode && activeScan.progress && (
                <p>
                  {activeScan.progress.stage ? `Stage: ${activeScan.progress.stage}. ` : ''}
                  {activeScan.progress.message || 'Scanning — progress percentage unavailable.'}
                  {` Elapsed: ${formatElapsed(activeScan.progress.elapsed_seconds)}.`}
                  {activeScan.progress.estimated_remaining_seconds != null
                    ? ` Estimated remaining: ${formatElapsed(activeScan.progress.estimated_remaining_seconds)}.`
                    : ''}
                </p>
              )}
              <p>{demoMode ? statusDescription(activeScan.status) : `Backend status: ${activeScan.status}.`}</p>
              {!demoMode && (
                <section className="scan-activity" aria-label="Live scan activity">
                  <h3>Live scan activity</h3>
                  {activeScan.events?.length ? (
                    <ol>
                      {activeScan.events.map((event) => (
                        <li className={`activity-${event.eventType}`} key={event.sequence}>
                          <time dateTime={event.timestamp}>
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </time>
                          <span>{event.message}</span>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p>Waiting for Nmap activity.</p>
                  )}
                </section>
              )}
              {activeScan.status === 'completed' && (
                <p className="success-note">{demoMode ? 'Demo results are ready. They are not live scan output.' : 'Live backend results are ready.'}</p>
              )}
            </div>
          ) : (
            <p className="simulation-note">
              {demoMode
                ? 'Submit the form to see queued, running, analyzing, and completed states. The sequence is simulated locally.'
                : 'Submit the form to run an authorized backend scan. Progress is reported by the API.'}
            </p>
          )}
          <div className="simulation-steps" aria-label={demoMode ? 'Demo lifecycle' : 'Scan lifecycle'}>
            {(demoMode ? ['Queued', 'Running', 'Analyzing', 'Complete'] : ['Queued', 'Running', 'Complete']).map((step, index) => (
              <div className="simulation-step" key={step}>
                <span className={demoMode
                  ? (activeScan?.progress >= [0, 35, 75, 100][index] ? 'step-dot is-reached' : 'step-dot')
                  : (activeScan && (index === 0 || (index === 1 && activeScan.status === 'running') || (index === 2 && activeScan.status === 'completed')) ? 'step-dot is-reached' : 'step-dot')} />
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

function formatElapsed(seconds) {
  if (!Number.isFinite(seconds)) return 'Unavailable'
  const total = Math.max(0, Math.round(seconds))
  const minutes = Math.floor(total / 60)
  const remaining = total % 60
  return minutes ? `${minutes}m ${remaining}s` : `${remaining}s`
}

export default StartScan
