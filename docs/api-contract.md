# Nmap Automator API contract

The API validates target syntax and applies `SCAN_TARGET_ALLOWLIST` when set;
production requires this comma-separated allowlist and rejects all other
targets. Operators must only scan systems they own or are explicitly
authorized to assess. Nmap execution remains restricted to fixed profiles,
shell-free argument lists, timeouts, and bounded queue capacity. CORS origins
are configured through `FRONTEND_CORS_ORIGINS` and default to
`http://localhost:5173`. CORS is not an authorization mechanism.

`POST /api/auth/login` accepts `{"password":"..."}` and returns a signed,
expiring bearer token. Set `APP_ACCESS_PASSWORD` and `APP_AUTH_SECRET` only in
the backend environment. Every `/api/scans` endpoint requires
`Authorization: Bearer <token>`. Login attempts are rate limited. `GET /health`
is public and intended for health checks. Production (`APP_ENV=production`)
requires a non-placeholder password of at least 12 characters, a high-entropy
signing secret of at least 32 characters, explicit HTTPS frontend origins, and
a non-empty target allowlist. CORS is not authentication. Login throttling is
bounded and process-local; it is not shared between backend instances.

Scans and their history are stored in memory only and disappear when the
process restarts. Work is bounded by the in-memory manager and returns
`429 Too Many Requests` when capacity is exhausted.

The default maximum number of simultaneously executing scans is 2. Set
`MAX_CONCURRENT_SCANS` to a positive value from 1 through 16 to change it.
`MAX_PENDING_SCANS` controls total queued plus running capacity and defaults to
4 (maximum 64). Jobs beyond that capacity receive `429`; jobs within capacity
remain `queued` until a worker is available.

Nmap execution has bounded, profile-specific timeouts. The seven profiles are:

| ID | Scope | Default timeout |
| --- | --- | --- |
| `quick_tcp` | 100 common TCP ports (`-F`) | 60 seconds |
| `basic_tcp` | TCP ports 1-1000 | 120 seconds |
| `full_tcp` | TCP ports 1-65535, faster timing (`-T4`), maximum 3 retries | 900 seconds |
| `service_detection` | TCP ports 1-1000 with light service detection | 300 seconds |
| `comprehensive_tcp` | TCP ports 1-65535 with light service detection, faster timing (`-T4`), maximum 3 retries | 1200 seconds |
| `udp_top_100` | 100 common UDP ports (`-F`) | 600 seconds |
| `tcp_udp_common` | 100 common TCP and UDP ports (`-F`) | 600 seconds |

Timeouts can be overridden with `NMAP_TIMEOUT_<PROFILE_ID_IN uppercase>`.
Values must be positive integers and may not exceed the hard maximum of 1800
seconds. UDP scans may require elevated privileges and can be slower or less
deterministic than TCP scans. A timeout fails the scan and does not produce
successful or partial results.

## `POST /api/scans`

Request:

```json
{"target": "127.0.0.1", "profile": "basic_tcp"}
```

`profile` is one of the seven registered IDs above. The response is
`202 Accepted`:

```json
{
  "scan_id": "uuid",
  "target": "127.0.0.1",
  "profile": "basic_tcp",
  "status": "queued",
  "created_at": "2026-10-18T00:00:00Z",
  "started_at": null,
  "completed_at": null,
  "summary": null,
  "error": null
}
```

Invalid request syntax returns `422`. Queue saturation returns `429`.

## `GET /api/scans/{scan_id}`

Returns `200` with the scan response above. `status` is `queued`, `running`,
`completed`, `failed`, or `cancelled`. `started_at` is populated when a worker actually
starts Nmap and remains `null` while queued. Completed scans include `summary`; failed and
cancelled scans include a sanitized `error`. Unknown IDs return `404`.

Every response includes a `progress` object:

```json
{
  "stage": "connect scan",
  "percent": 37.5,
  "elapsed_seconds": 12.4,
  "estimated_remaining_seconds": null,
  "last_update_at": "2026-10-20T12:00:05Z",
  "message": "Stats: About 37.50% done"
}
```

Progress is parsed from Nmap's periodic statistics and XML task-progress
events emitted by the fixed `--stats-every 5s` argument. `percent` and ETA are
`null` unless Nmap reports them reliably. Percentages can reset between Nmap
stages and are not a guaranteed whole-scan percentage. Elapsed time is
measured from the worker's Nmap process start. A stale statistics stream is
reported through `message`; it does not imply that the process is stuck.

## `GET /api/scans/{scan_id}/events?after=<sequence>`

Returns bounded, scan-specific activity events produced while Nmap runs.
`after` is an optional sequence cursor; only events with a greater sequence
number are returned. Events may be requested before the scan reaches a
terminal state, so clients can poll independently of the status endpoint.

```json
{
  "scan_id": "uuid",
  "events": [
    {
      "sequence": 4,
      "timestamp": "2026-10-20T12:00:03Z",
      "event_type": "port_discovered",
      "message": "Discovered port 443/tcp."
    }
  ],
  "next_sequence": 5
}
```

`next_sequence` is the next sequence number the server will assign. Since
`after` is exclusive, clients should advance their cursor to the highest event
sequence actually received, not to `next_sequence`.

Supported event types include `info`, `stage`, `progress`,
`port_discovered`, `warning`, `error`, and `completed`. Messages are
sanitized and length-limited; command lines, environment data, and terminal
escape sequences are not exposed. Event history is bounded in memory, so a
late client may receive only the newest retained events. Failed or timed-out
scans retain their activity and error events but do not receive a
`completed` event. Unknown IDs return `404`.

Summary fields are counts of ports reported by Nmap:

- `reported_ports`
- `open_ports`
- `closed_ports`
- `filtered_ports`
- `unavailable_state_ports`

The API does not claim that every port was checked.

## `GET /api/scans/{scan_id}/ports`

Returns `200` after successful completion:

```json
{
  "scan_id": "uuid",
  "target": "127.0.0.1",
  "profile": "basic_tcp",
  "status": "completed",
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": "ssh",
      "product": null,
      "version": null,
      "detection_method": "probed",
      "service_confidence": 10
    }
  ]
}
```

Queued, running, and failed scans return `409`; unknown IDs return `404`.
Cancelled scans return the complete port records captured before cancellation. These are
partial observations; absence of a port does not imply it is closed.

## `GET /api/scans/{scan_id}/findings`

Returns `200` for completed or cancelled scans. Cancelled-scan findings use
only observations captured before cancellation. Findings are generated from the
stored parsed scan result by transparent rules. An open port alone is never a
finding. A service name inferred from Nmap's port table (`method="table"`),
an ambiguous/unsupported method, or missing/invalid confidence produces no
service finding. Findings require an actively probed service with confidence
at least 7/10.

```json
{
  "scan_id": "uuid",
  "target": "127.0.0.1",
  "profile": "basic_tcp",
  "status": "completed",
  "findings": [
    {
      "rule_id": "service.telnet-exposed",
      "title": "Open Telnet service observed",
      "severity": "high",
      "description": "Nmap actively probed and identified an open Telnet service.",
      "evidence": "Open tcp/23; Nmap actively probed service name: telnet; network exposure context was not established.",
      "risk_explanation": "Telnet commonly transmits credentials and session data without transport encryption.",
      "recommended_remediation": "Disable Telnet or replace it with an approved encrypted remote-access protocol.",
      "confidence": "high",
      "verification_status": "requires_verification"
    }
  ]
}
```

An empty `findings` list means no implemented rule matched the available
evidence; it does not prove that the target is secure. Findings describe
observations on the scanned target and do not establish external exposure or
prove a vulnerability. Queued, running, and failed scans return `409`;
cancelled scans return findings derived only from captured port observations;
unknown IDs return `404`.

## `GET /api/scans/{scan_id}/report?format=html|json|pdf`

Returns a report for a completed or cancelled scan. `format` defaults to `html`.
Cancelled-scan reports are prominently marked incomplete and include only captured
port observations, rule-based findings from those observations, the progress state at
stop time, and retained terminal events. Unscanned ports and services are unknown.

| Format | Content type | Filename |
| --- | --- | --- |
| `html` | `text/html; charset=utf-8` | `security-assessment-<scan_id>.html` |
| `json` | `application/json` | `security-assessment-<scan_id>.json` |
| `pdf` | `application/pdf` | `security-assessment-<scan_id>.pdf` |

The JSON report contains `schema_version`, `report_generated_at`, `scan`,
`summary`, `progress_at_end`, `ports`, `findings`, `terminal_events`, and `limitations`. Port entries preserve
service, product, version, detection method, and confidence values as
`null` when unavailable. Findings are the stored rule-based findings returned
by the findings endpoint; report generation does not perform new analysis.

Queued, running, and failed scans return `409`; unknown IDs return `404`;
unsupported formats return `400`. The HTML and PDF reports use the same stored
scan data as the JSON report. PDF generation uses ReportLab and does not
require external resources. Reports do not establish external reachability or
claim that an empty findings list means the target is secure.

## Development server

From the repository root:

```powershell
$env:PYTHONPATH = "E:\Projects\nmap"
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Do not bind this development service to a public interface.
