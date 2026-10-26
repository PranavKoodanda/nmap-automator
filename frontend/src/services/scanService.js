import {
  DEMO_FINDINGS,
  DEMO_MODE,
  DEMO_PORTS,
  INITIAL_DEMO_SCANS,
} from './mockData.js'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001').replace(/\/$/, '')
const REAL_STORAGE_KEY = 'nmap-automator.real-scan-ids.v1'
const DEMO_STORAGE_KEY = 'nmap-automator.demo-scans.v1'
const POLL_INTERVAL_MS = 1000
const POLL_TIMEOUT_MS = 35 * 60 * 1000
const TOKEN_KEY = 'nmap-automator.access-token.v1'

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

const clone = (value) => JSON.parse(JSON.stringify(value))
const wait = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds))
export const isDemoMode = () => DEMO_MODE

function readDemoScans() {
  const stored = window.localStorage.getItem(DEMO_STORAGE_KEY)
  if (!stored) return clone(INITIAL_DEMO_SCANS)
  const scans = JSON.parse(stored)
  if (!Array.isArray(scans)) throw new Error('Saved demonstration history is invalid.')
  return scans
}

function writeDemoScans(scans) {
  window.localStorage.setItem(DEMO_STORAGE_KEY, JSON.stringify(scans))
}

function readRealScanIds() {
  const stored = window.localStorage.getItem(REAL_STORAGE_KEY)
  if (!stored) return []
  const ids = JSON.parse(stored)
  if (!Array.isArray(ids) || ids.some((id) => typeof id !== 'string')) {
    throw new Error('Saved real scan history is invalid.')
  }
  return ids
}

function writeRealScanIds(ids) {
  window.localStorage.setItem(REAL_STORAGE_KEY, JSON.stringify([...new Set(ids)]))
}

async function request(path, options = {}) {
  let response
  try {
    const token = window.sessionStorage.getItem(TOKEN_KEY)
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers },
    })
  } catch {
    throw new ApiError('The backend could not be reached. Start the API server and try again.')
  }

  if (!response.ok) {
    if (response.status === 401 && path !== '/api/auth/login') {
      window.sessionStorage.removeItem(TOKEN_KEY)
      window.dispatchEvent(new Event('nmap-auth-expired'))
    }
    let detail = `Backend request failed (${response.status}).`
    try {
      const body = await response.json()
      if (typeof body.detail === 'string') detail = body.detail
    } catch {
      // Keep the status-based message when the response is not JSON.
    }
    throw new ApiError(detail, response.status)
  }
  return response
}

export function hasSessionToken() {
  return Boolean(window.sessionStorage.getItem(TOKEN_KEY))
}

export async function login(password) {
  const response = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ password }) })
  const payload = await response.json()
  window.sessionStorage.setItem(TOKEN_KEY, payload.access_token)
}

export function logout() {
  window.sessionStorage.removeItem(TOKEN_KEY)
}

function adaptPort(port) {
  return {
    port: port.port,
    protocol: port.protocol,
    state: port.state,
    service: port.service,
    product: port.product,
    version: port.version,
    detectionMethod: port.detection_method,
    serviceConfidence: port.service_confidence,
  }
}

function adaptFinding(finding) {
  return {
    id: finding.rule_id,
    ruleId: finding.rule_id,
    severity: finding.severity,
    title: finding.title,
    description: finding.description,
    evidence: finding.evidence,
    riskExplanation: finding.risk_explanation,
    remediation: finding.recommended_remediation,
    confidence: finding.confidence,
    verificationStatus: finding.verification_status,
  }
}

function adaptProgress(progress) {
  if (!progress || typeof progress !== 'object') {
    return {
      stage: null,
      percent: null,
      elapsed_seconds: 0,
      estimated_remaining_seconds: null,
      last_update_at: null,
      message: 'Waiting for Nmap progress statistics.',
    }
  }
  const percent = typeof progress.percent === 'number' && Number.isFinite(progress.percent)
    ? Math.min(100, Math.max(0, progress.percent))
    : null
  const elapsed = typeof progress.elapsed_seconds === 'number' && Number.isFinite(progress.elapsed_seconds)
    ? Math.max(0, progress.elapsed_seconds)
    : 0
  const remaining = typeof progress.estimated_remaining_seconds === 'number' &&
    Number.isFinite(progress.estimated_remaining_seconds)
    ? Math.max(0, progress.estimated_remaining_seconds)
    : null
  return {
    stage: typeof progress.stage === 'string' ? progress.stage : null,
    percent,
    elapsed_seconds: elapsed,
    estimated_remaining_seconds: remaining,
    last_update_at: progress.last_update_at || null,
    message: typeof progress.message === 'string' && progress.message
      ? progress.message
      : 'Waiting for Nmap progress statistics.',
  }
}

function adaptScan(scan, ports = [], findings = [], events = [], eventCursor = 0) {
  return {
    id: scan.scan_id,
    target: scan.target,
    profile: scan.profile,
    status: scan.status,
    mode: 'api',
    createdAt: scan.created_at,
    startedAt: scan.started_at || scan.created_at,
    completedAt: scan.completed_at,
    summary: scan.summary,
    error: scan.error,
    progress: adaptProgress(scan.progress),
    ports,
    findings,
    events,
    eventCursor,
  }
}

function adaptEvents(payload) {
  return (payload.events || []).map((event) => ({
    sequence: event.sequence,
    timestamp: event.timestamp,
    eventType: event.event_type,
    message: event.message,
  }))
}

async function getApiEvents(scanId, after = 0) {
  const response = await request(
    `/api/scans/${encodeURIComponent(scanId)}/events?after=${after}`,
  )
  const payload = await response.json()
  const events = adaptEvents(payload)
  const cursor = events.reduce(
    (latest, event) => Math.max(latest, event.sequence),
    after,
  )
  return { events, cursor }
}

async function getApiScan(scanId) {
  const scanResponse = await request(`/api/scans/${encodeURIComponent(scanId)}`)
  const scan = await scanResponse.json()
  const eventBatch = await getApiEvents(scanId, 0)
  if (!['completed', 'cancelled'].includes(scan.status)) {
    return adaptScan(scan, [], [], eventBatch.events, eventBatch.cursor)
  }

  const [portsResponse, findingsResponse] = await Promise.all([
    request(`/api/scans/${encodeURIComponent(scanId)}/ports`),
    request(`/api/scans/${encodeURIComponent(scanId)}/findings`),
  ])
  const ports = (await portsResponse.json()).ports.map(adaptPort)
  const findings = (await findingsResponse.json()).findings.map(adaptFinding)
  return adaptScan(scan, ports, findings, eventBatch.events, eventBatch.cursor)
}

export async function getScanActivity(scanId, after = 0) {
  const [scanResponse, eventBatch] = await Promise.all([
    request(`/api/scans/${encodeURIComponent(scanId)}`),
    getApiEvents(scanId, after),
  ])
  const scan = adaptScan(await scanResponse.json())
  let events = eventBatch.events
  let cursor = eventBatch.cursor
  if (['completed', 'failed', 'cancelled'].includes(scan.status)) {
    const finalBatch = await getApiEvents(scanId, cursor)
    events = [...events, ...finalBatch.events]
    cursor = finalBatch.cursor
  }
  return {
    scan,
    events,
    cursor,
  }
}

export async function stopScan(scanId) {
  if (DEMO_MODE) throw new Error('Stopping scans is available in live API mode.')
  const response = await request(`/api/scans/${encodeURIComponent(scanId)}/stop`, { method: 'POST' })
  const scan = adaptScan(await response.json())
  const eventBatch = await getApiEvents(scanId, 0)
  scan.events = eventBatch.events
  scan.eventCursor = eventBatch.cursor
  return scan
}

async function listApiScans() {
  const ids = readRealScanIds()
  const results = await Promise.all(ids.map(async (id) => {
    try {
      return await getApiScan(id)
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null
      throw error
    }
  }))
  const validScans = results.filter(Boolean)
  writeRealScanIds(validScans.map((scan) => scan.id))
  return validScans
}

async function startApiScan(target, profile, onUpdate, onAccepted) {
  const response = await request('/api/scans', {
    method: 'POST',
    body: JSON.stringify({ target, profile }),
  })
  const created = await response.json()
  const ids = readRealScanIds()
  writeRealScanIds([created.scan_id, ...ids])
  let adapted = adaptScan(created)
  let events = []
  onUpdate?.(adapted)
  onAccepted?.(adapted)
  let cursor = 0

  const deadline = Date.now() + POLL_TIMEOUT_MS
  let current = created
  while (!['completed', 'failed', 'cancelled'].includes(current.status)) {
    if (Date.now() >= deadline) throw new ApiError('The scan polling timeout was reached.')
    await wait(POLL_INTERVAL_MS)
    const statusResponse = await request(`/api/scans/${encodeURIComponent(created.scan_id)}`)
    current = await statusResponse.json()
    const eventBatch = await getApiEvents(created.scan_id, cursor)
    cursor = eventBatch.cursor
    adapted = adaptScan(current)
    events = [...events, ...eventBatch.events]
    adapted.events = events
    adapted.eventCursor = cursor
    onUpdate?.(adapted)
  }

  const scan = await getApiScan(created.scan_id)
  const finalEvents = await getApiEvents(created.scan_id, cursor)
  events = [...events, ...finalEvents.events]
  scan.events = events
  scan.eventCursor = finalEvents.cursor
  onUpdate?.(scan)
  if (scan.status === 'failed' || scan.status === 'cancelled') {
    throw new ApiError(scan.error || 'The backend scan did not complete.')
  }
  return scan
}

function notify(onUpdate, scan) {
  onUpdate?.(clone(scan))
}

async function listDemoScans() {
  await wait(180)
  return clone(readDemoScans())
}

async function startDemoScan(target, profile, onUpdate) {
  const scans = readDemoScans()
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
  writeDemoScans(scans)
  notify(onUpdate, scan)
  await wait(450)
  scan.status = 'running'
  scan.progress = 35
  writeDemoScans(scans)
  notify(onUpdate, scan)
  await wait(500)
  scan.status = 'analyzing'
  scan.progress = 75
  writeDemoScans(scans)
  notify(onUpdate, scan)
  await wait(450)
  scan.status = 'completed'
  scan.progress = 100
  scan.completedAt = new Date().toISOString()
  scan.ports = clone(DEMO_PORTS)
  scan.findings = clone(DEMO_FINDINGS)
  writeDemoScans(scans)
  notify(onUpdate, scan)
  return clone(scan)
}

export function listScans() {
  return DEMO_MODE ? listDemoScans() : listApiScans()
}

export function getScan(scanId) {
  return DEMO_MODE
    ? Promise.resolve(clone(readDemoScans().find((scan) => scan.id === scanId) ?? null))
    : getApiScan(scanId)
}

export function startScan(target, profile, onUpdate, onAccepted) {
  return DEMO_MODE
    ? startDemoScan(target, profile, onUpdate)
    : startApiScan(target, profile, onUpdate, onAccepted)
}

export async function downloadReport(scan, format = 'html') {
  if (DEMO_MODE) return downloadDemoReport(scan, format)
  const response = await request(`/api/scans/${encodeURIComponent(scan.id)}/report?format=${encodeURIComponent(format)}`)
  const blob = await response.blob()
  const disposition = response.headers.get('Content-Disposition') || ''
  const filename = disposition.match(/filename="?([^"]+)"?/)?.[1] || `security-assessment-${scan.id}.${format}`
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
  return { filename }
}

async function downloadDemoReport(scan, format) {
  if (format !== 'pdf') {
    throw new Error('Demonstration mode supports PDF export only.')
  }
  const { downloadDemoReportPdf } = await import('./pdfReport.js')
  return downloadDemoReportPdf(scan)
}

export function getModeLabel() {
  return DEMO_MODE ? 'DEMO MODE' : 'LIVE API MODE'
}

export function createDemoReport(scan) {
  if (!scan || scan.mode !== 'demo' || scan.status !== 'completed') {
    throw new Error('A completed demonstration scan is required for this report.')
  }
  return {
    reportType: 'DEMONSTRATION ONLY',
    generatedAt: new Date().toISOString(),
    scan: clone(scan),
    disclaimer: 'This report contains demonstration data only. No network scan was performed.',
  }
}
