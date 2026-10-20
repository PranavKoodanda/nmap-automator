import {
  DEMO_FINDINGS,
  DEMO_MODE,
  DEMO_PORTS,
  INITIAL_DEMO_SCANS,
} from './mockData.js'

const STORAGE_KEY = 'nmap-automator.demo-scans.v1'
const clone = (value) => JSON.parse(JSON.stringify(value))
const wait = (milliseconds) =>
  new Promise((resolve) => window.setTimeout(resolve, milliseconds))

function readScans() {
  const stored = window.localStorage.getItem(STORAGE_KEY)
  if (!stored) return clone(INITIAL_DEMO_SCANS)

  const scans = JSON.parse(stored)
  if (!Array.isArray(scans)) throw new Error('Saved demo scan history is invalid.')
  return scans
}

function writeScans(scans) {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(scans))
}

function notify(onUpdate, scan) {
  onUpdate?.(clone(scan))
}

export async function listScans() {
  await wait(180)
  return clone(readScans())
}

export async function getScan(scanId) {
  const scans = readScans()
  return clone(scans.find((scan) => scan.id === scanId) ?? null)
}

export async function startScan(target, profile, onUpdate) {
  if (!DEMO_MODE) throw new Error('The demo scan service is disabled.')

  const scans = readScans()
  const scan = {
    id: `demo-${crypto.randomUUID()}`,
    target,
    profile,
    status: 'queued',
    mode: 'demo',
    progress: 0,
    startedAt: new Date().toISOString(),
    completedAt: null,
    ports: [],
    findings: [],
  }

  scans.unshift(scan)
  writeScans(scans)
  notify(onUpdate, scan)

  await wait(450)
  scan.status = 'running'
  scan.progress = 35
  writeScans(scans)
  notify(onUpdate, scan)

  await wait(500)
  scan.status = 'analyzing'
  scan.progress = 75
  writeScans(scans)
  notify(onUpdate, scan)

  await wait(450)
  scan.status = 'completed'
  scan.progress = 100
  scan.completedAt = new Date().toISOString()
  scan.ports = clone(DEMO_PORTS)
  scan.findings = clone(DEMO_FINDINGS)
  writeScans(scans)
  notify(onUpdate, scan)

  return clone(scan)
}

export function createDemoReport(scan) {
  if (!scan || scan.mode !== 'demo' || scan.status !== 'completed') {
    throw new Error('A completed demonstration scan is required for this report.')
  }

  return {
    reportType: 'DEMONSTRATION ONLY',
    generatedAt: new Date().toISOString(),
    scan: clone(scan),
    disclaimer:
      'This report contains demonstration data only. No network scan was performed.',
  }
}