import { useEffect, useState } from 'react'
import AppLayout from './components/AppLayout'
import Dashboard from './pages/Dashboard'
import ReportsView from './pages/ReportsView'
import ResultsView from './pages/ResultsView'
import StartScan from './pages/StartScan'
import { DEMO_MODE, SCAN_PROFILES } from './services/mockData'
import { listScans, startScan } from './services/scanService'
import './AppLayout.css'

function App() {
  const [page, setPage] = useState('dashboard')
  const [scans, setScans] = useState([])
  const [selectedScanId, setSelectedScanId] = useState(null)
  const [activeScan, setActiveScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [scanError, setScanError] = useState('')

  async function refreshScans() {
    setLoading(true)
    setLoadError('')
    try {
      setScans(await listScans())
    } catch {
      setLoadError('Demo history could not be loaded from this browser.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let mounted = true
    listScans()
      .then((items) => {
        if (mounted) setScans(items)
      })
      .catch(() => {
        if (mounted) setLoadError('Demo history could not be loaded from this browser.')
      })
      .finally(() => {
        if (mounted) setLoading(false)
      })

    return () => {
      mounted = false
    }
  }, [])

  async function handleStartScan(target, profile) {
    setScanError('')
    setActiveScan(null)
    try {
      const completedScan = await startScan(target, profile, (updatedScan) => {
        setActiveScan(updatedScan)
        setScans((currentScans) => [
          updatedScan,
          ...currentScans.filter((scan) => scan.id !== updatedScan.id),
        ])
      })
      setSelectedScanId(completedScan.id)
      setPage('results')
    } catch {
      setScanError('The demo scan could not be saved. Check browser storage and try again.')
      throw new Error('The demo scan could not be completed.')
    }
  }

  function openScan(scan) {
    setSelectedScanId(scan.id)
    setPage('results')
  }

  const selectedScan = scans.find((scan) => scan.id === selectedScanId) ?? null

  return (
    <AppLayout page={page} onNavigate={setPage} demoMode={DEMO_MODE}>
      {loadError && (
        <div className="alert alert-error" role="alert">
          <span>{loadError}</span>
          <button className="text-button" type="button" onClick={refreshScans}>Retry</button>
        </div>
      )}
      {loading && scans.length === 0 ? (
        <div className="state-panel" role="status">Loading demonstration data…</div>
      ) : page === 'dashboard' ? (
        <Dashboard scans={scans} onOpenScan={openScan} onNavigate={setPage} />
      ) : page === 'start-scan' ? (
        <StartScan
          profiles={SCAN_PROFILES}
          activeScan={activeScan}
          error={scanError}
          onStartScan={handleStartScan}
        />
      ) : page === 'history' ? (
        <Dashboard scans={scans} onOpenScan={openScan} onNavigate={setPage} historyOnly />
      ) : page === 'results' ? (
        <ResultsView scan={selectedScan} onNavigate={setPage} />
      ) : (
        <ReportsView scans={scans} onOpenScan={openScan} />
      )}
    </AppLayout>
  )
}

export default App
