import { useEffect, useRef, useState } from 'react'
import AppLayout from './components/AppLayout'
import Dashboard from './pages/Dashboard'
import ReportsView from './pages/ReportsView'
import ResultsView from './pages/ResultsView'
import StartScan from './pages/StartScan'
import ScanActivityView from './pages/ScanActivityView'
import { SCAN_PROFILES } from './services/mockData'
import {
  getModeLabel,
  getScanActivity,
  isDemoMode,
  listScans,
  startScan,
  stopScan as requestStopScan,
} from './services/scanService'
import './AppLayout.css'

const HOSTED_SCAN_PROFILES = SCAN_PROFILES.filter(
  (profile) => !['udp_top_100', 'tcp_udp_common'].includes(profile.id),
)

function App() {
  const [page, setPage] = useState('dashboard')
  const [scans, setScans] = useState([])
  const [selectedScanId, setSelectedScanId] = useState(null)
  const [activityScanId, setActivityScanId] = useState(null)
  const [activeScan, setActiveScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [scanError, setScanError] = useState('')
  const [connectionState, setConnectionState] = useState('checking')
  const demoMode = isDemoMode()
  const scansRef = useRef(scans)
  const eventCursorsRef = useRef(new Map())
  const monitorInFlightRef = useRef(false)

  useEffect(() => {
    scansRef.current = scans
  }, [scans])

  async function refreshScans({ showLoading = true } = {}) {
    if (showLoading) setLoading(true)
    setLoadError('')
    try {
      setScans(await listScans())
      setConnectionState(demoMode ? 'demo' : 'connected')
    } catch (error) {
      setConnectionState(demoMode ? 'demo' : 'disconnected')
      setLoadError(error.message)
    } finally {
      if (showLoading) setLoading(false)
    }
  }

  useEffect(() => {
    let mounted = true
    listScans()
      .then((items) => {
        if (mounted) {
          setScans(items)
          setConnectionState(demoMode ? 'demo' : 'connected')
        }
      })
      .catch((error) => {
        if (mounted) {
          setConnectionState(demoMode ? 'demo' : 'disconnected')
          setLoadError(error.message)
        }
      })
      .finally(() => {
        if (mounted) setLoading(false)
      })

    return () => {
      mounted = false
    }
  }, [demoMode])

  useEffect(() => {
    if (demoMode) return undefined
    let cancelled = false
    const pollActiveScans = async () => {
      if (cancelled || monitorInFlightRef.current) return
      const activeScans = scansRef.current.filter(
        (scan) => scan.status === 'queued' || scan.status === 'running',
      )
      if (!activeScans.length) return
      monitorInFlightRef.current = true
      try {
        await Promise.all(activeScans.map(async (scan) => {
          const cursor = eventCursorsRef.current.get(scan.id) ?? scan.eventCursor ?? 0
          const update = await getScanActivity(scan.id, cursor)
          eventCursorsRef.current.set(scan.id, update.cursor)
          if (cancelled) return
          setScans((currentScans) => currentScans.map((current) => (
            current.id !== scan.id
              ? current
              : mergeMonitoredScan(current, update.scan, update.events, update.cursor)
          )))
        }))
        setConnectionState('connected')
      } catch (error) {
        if (!cancelled) {
          setConnectionState('disconnected')
          setLoadError(error.message)
        }
      } finally {
        monitorInFlightRef.current = false
      }
    }
    void pollActiveScans()
    const interval = window.setInterval(() => void pollActiveScans(), 1000)
    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [demoMode])

  async function handleStartScan(target, profile, onAccepted) {
    setScanError('')
    setActiveScan(null)
    try {
      const completedScan = await startScan(target, profile, (updatedScan) => {
        setActiveScan(updatedScan)
        setScans((currentScans) => [
          updatedScan,
          ...currentScans.filter((scan) => scan.id !== updatedScan.id),
        ])
      }, onAccepted)
      setSelectedScanId(completedScan.id)
      setPage('results')
    } catch (error) {
      setScanError(error.message)
      throw new Error('The scan could not be completed.', { cause: error })
    }
  }

  function openScan(scan) {
    setSelectedScanId(scan.id)
    setPage('results')
  }

  async function handleStopScan(scanId) {
    try {
      const stopped = await requestStopScan(scanId)
      eventCursorsRef.current.set(scanId, stopped.eventCursor)
      setScans((currentScans) => [stopped, ...currentScans.filter((scan) => scan.id !== scanId)])
      setActiveScan((current) => current?.id === scanId ? stopped : current)
    } catch (error) {
      setLoadError(error.message)
    }
  }

  function openActivity(scan) {
    setActivityScanId(scan.id)
    setPage('activity')
  }

  const selectedScan = scans.find((scan) => scan.id === selectedScanId) ?? null

  return (
    <AppLayout page={page} onNavigate={setPage} demoMode={demoMode} modeLabel={getModeLabel()} connectionState={connectionState}>
      {loadError && (
        <div className="alert alert-error" role="alert">
          <span>{loadError}</span>
          <button className="text-button" type="button" onClick={refreshScans}>Retry</button>
        </div>
      )}
      {loading && scans.length === 0 ? (
        <div className="state-panel" role="status">
          {demoMode ? 'Loading demonstration data…' : 'Connecting to the backend…'}
        </div>
      ) : page === 'dashboard' ? (
        <Dashboard scans={scans} onOpenActivity={openActivity} onStopScan={handleStopScan} onNavigate={setPage} demoMode={demoMode} />
      ) : page === 'start-scan' ? (
        <StartScan
          profiles={import.meta.env.PROD ? HOSTED_SCAN_PROFILES : SCAN_PROFILES}
          activeScan={activeScan}
          error={scanError}
          onStartScan={handleStartScan}
          demoMode={demoMode}
        />
      ) : page === 'history' ? (
        <Dashboard scans={scans} onOpenActivity={openActivity} onStopScan={handleStopScan} onNavigate={setPage} historyOnly demoMode={demoMode} />
      ) : page === 'activity' ? (
        <ScanActivityView
          scan={scans.find((item) => item.id === activityScanId) ?? null}
          onBack={() => setPage('history')}
        />
      ) : page === 'results' ? (
        <ResultsView scan={selectedScan} onNavigate={setPage} demoMode={demoMode} />
      ) : (
        <ReportsView scans={scans} onOpenScan={openScan} demoMode={demoMode} />
      )}
    </AppLayout>
  )
}

function mergeMonitoredScan(current, update, newEvents, cursor) {
  const eventsBySequence = new Map(
    [...(current.events || []), ...newEvents].map((event) => [event.sequence, event]),
  )
  return {
    ...current,
    ...update,
    ports: current.ports.length ? current.ports : update.ports,
    findings: current.findings.length ? current.findings : update.findings,
    events: [...eventsBySequence.values()].sort((left, right) => left.sequence - right.sequence),
    eventCursor: cursor,
  }
}

export default App
