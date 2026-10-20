export const DEMO_MODE = true

export const SCAN_PROFILES = [
  {
    id: 'quick-inventory',
    label: 'Quick inventory',
    description: 'A short demonstration of host and common-port inventory.',
  },
  {
    id: 'standard-review',
    label: 'Standard review',
    description: 'A balanced demonstration profile with service metadata.',
  },
  {
    id: 'service-details',
    label: 'Service details',
    description: 'A demonstration focused on service and version fields.',
  },
]

export const DEMO_PORTS = [
  {
    port: 22,
    protocol: 'tcp',
    state: 'open',
    service: 'ssh',
    product: 'OpenSSH',
    version: '9.6',
  },
  {
    port: 80,
    protocol: 'tcp',
    state: 'open',
    service: 'http',
    product: 'Example HTTP service',
    version: null,
  },
  {
    port: 443,
    protocol: 'tcp',
    state: 'filtered',
    service: null,
    product: null,
    version: null,
  },
  {
    port: 3306,
    protocol: 'tcp',
    state: 'closed',
    service: 'mysql',
    product: null,
    version: null,
  },
]

export const DEMO_FINDINGS = [
  {
    id: 'demo-banner-observed',
    severity: 'Info',
    title: 'Service banner observed',
    description:
      'A service banner is present in this demonstration data. This observation does not prove a vulnerability.',
  },
]

export const INITIAL_DEMO_SCANS = [
  {
    id: 'demo-scan-001',
    target: '192.0.2.10',
    profile: 'standard-review',
    status: 'completed',
    mode: 'demo',
    progress: 100,
    startedAt: '2026-10-17T14:20:00.000Z',
    completedAt: '2026-10-17T14:20:08.000Z',
    ports: DEMO_PORTS,
    findings: DEMO_FINDINGS,
  },
  {
    id: 'demo-scan-002',
    target: '198.51.100.24',
    profile: 'quick-inventory',
    status: 'completed',
    mode: 'demo',
    progress: 100,
    startedAt: '2026-10-16T09:45:00.000Z',
    completedAt: '2026-10-16T09:45:05.000Z',
    ports: DEMO_PORTS.slice(0, 2),
    findings: [],
  },
]