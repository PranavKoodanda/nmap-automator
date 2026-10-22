export const DEMO_MODE = import.meta.env.VITE_API_MODE === 'demo'

export const SCAN_PROFILES = [
  {
    id: 'quick_tcp',
    label: 'Quick TCP scan',
    description: 'Quickly check 100 common TCP ports. · Fast',
  },
  {
    id: 'basic_tcp',
    label: 'Basic TCP scan',
    description: 'Basic TCP port discovery using the existing scan configuration. · Medium',
  },
  {
    id: 'full_tcp',
    label: 'Full TCP scan',
    description: 'Scan the complete TCP port range. · Long',
  },
  {
    id: 'service_detection',
    label: 'Service detection',
    description: 'Identify services and versions using the existing scan configuration. · Long',
  },
  {
    id: 'comprehensive_tcp',
    label: 'Comprehensive TCP scan',
    description: 'Scan all TCP ports and identify services and versions. · Very long',
  },
  {
    id: 'udp_top_100',
    label: 'UDP top ports scan',
    description: 'Check 100 common UDP ports. · Long',
  },
  {
    id: 'tcp_udp_common',
    label: 'Common TCP + UDP scan',
    description: 'Scan 100 common ports for both TCP and UDP. · Long',
  },
]

export const DEMO_PORTS = [
  { port: 22, protocol: 'tcp', state: 'open', service: 'ssh', product: 'OpenSSH', version: '9.6' },
  { port: 80, protocol: 'tcp', state: 'open', service: 'http', product: 'Example HTTP service', version: null },
  { port: 443, protocol: 'tcp', state: 'filtered', service: null, product: null, version: null },
  { port: 3306, protocol: 'tcp', state: 'closed', service: 'mysql', product: null, version: null },
]

export const DEMO_FINDINGS = [
  {
    id: 'demo-banner-observed',
    severity: 'Info',
    title: 'Service banner observed',
    description: 'A service banner is present in this demonstration data. This observation does not prove a vulnerability.',
  },
]

export const INITIAL_DEMO_SCANS = [
  {
    id: 'demo-scan-001',
    target: '192.0.2.10',
    profile: 'service_detection',
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
    profile: 'basic_tcp',
    status: 'completed',
    mode: 'demo',
    progress: 100,
    startedAt: '2026-10-16T09:45:00.000Z',
    completedAt: '2026-10-16T09:45:05.000Z',
    ports: DEMO_PORTS.slice(0, 2),
    findings: [],
  },
]
