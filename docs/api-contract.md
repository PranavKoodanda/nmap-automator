# Nmap Automator API contract

The development API is intentionally bounded for operator safety. It allows
loopback targets by default. Additional exact IP addresses or hostnames may be
provided through `TARGET_ALLOWLIST`; missing configuration never means
"allow all". CORS origins are configured through `FRONTEND_CORS_ORIGINS` and
default to `http://localhost:5173`. CORS is not an authorization mechanism.

Scans and their history are stored in memory only and disappear when the
process restarts. Work is bounded by the in-memory manager and returns
`429 Too Many Requests` when capacity is exhausted.

## `POST /api/scans`

Request:

```json
{"target": "127.0.0.1", "profile": "basic_tcp"}
```

`profile` is one of `basic_tcp` or `service_detection`. The response is
`202 Accepted`:

```json
{
  "scan_id": "uuid",
  "target": "127.0.0.1",
  "profile": "basic_tcp",
  "status": "queued",
  "created_at": "2026-10-18T00:00:00Z",
  "completed_at": null,
  "summary": null,
  "error": null
}
```

Invalid request syntax returns `422`. A target outside the configured policy
returns `403`. Queue saturation returns `429`.

## `GET /api/scans/{scan_id}`

Returns `200` with the scan response above. `status` is `queued`, `running`,
`completed`, or `failed`. Completed scans include `summary`; failed scans
include a sanitized `error`. Unknown IDs return `404`.

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

## `GET /api/scans/{scan_id}/findings`

Returns `200` after successful completion. Findings are generated from the
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
unknown IDs return `404`.

## Development server

From the repository root:

```powershell
$env:PYTHONPATH = "E:\Projects\nmap"
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Do not bind this development service to a public interface.
