# nmap-automator
A Python-based network security assessment tool that automates Nmap scanning, identifies open ports and services, analyzes potential security risks, and generates comprehensive security assessment reports through a web dashboard.

## Local development

The backend validates target syntax, uses only fixed scan profiles, and executes
Nmap without a shell. All scan endpoints require a password-issued bearer token.
Configure `APP_ACCESS_PASSWORD` and `APP_AUTH_SECRET` on the backend; the frontend
stores its short-lived token in session storage. `SCAN_TARGET_ALLOWLIST` can
restrict targets locally and is required in production. Only scan systems you
own or are explicitly authorized to assess. Keep the API bound to loopback
during development.

```powershell
$env:PYTHONPATH = "E:\Projects\nmap"
$env:APP_ACCESS_PASSWORD = "your-private-local-password"
$env:APP_AUTH_SECRET = "your-private-local-random-secret-at-least-32-bytes"
python -m pip install -r backend\requirements.txt
uvicorn backend.app.main:app --host 127.0.0.1 --port 8001
```

In a second terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

The frontend uses live API mode by default. Copy `frontend\.env.example` to
`frontend\.env.local` to configure the API URL. Set `VITE_API_MODE=demo` only
when explicitly previewing demonstration data.

## Render deployment

Deploy the repository's `Dockerfile` as a Render web service. Set backend
environment variables in the Render dashboard: `APP_ENV=production`,
`APP_ACCESS_PASSWORD` (a unique password of at least 12 characters),
`APP_AUTH_SECRET` (at least 32 random bytes), `FRONTEND_CORS_ORIGINS` (one or
more explicit HTTPS frontend origins; wildcards are rejected), and
`SCAN_TARGET_ALLOWLIST` (comma-separated IP addresses or hostnames you are
explicitly authorized to assess). Production startup fails closed if any
required setting is missing. Keep secrets out of the repository and all
`VITE_` variables. Configure the frontend's
`VITE_API_BASE_URL` to the backend URL at build time; it contains no secret.
`/health` remains available without a token for platform health checks.

Generate private production values locally with Python, then enter the output
directly in Render's backend environment settings (do not commit it):

```powershell
python -c "import secrets; print('APP_ACCESS_PASSWORD=' + secrets.token_urlsafe(24)); print('APP_AUTH_SECRET=' + secrets.token_urlsafe(48))"
```

The login-attempt limiter is process-local and its memory is bounded. Each
backend instance enforces its own limit; attempts are not shared across
instances, so this is not distributed rate limiting.

Completed scans support HTML, JSON, and PDF downloads through
`GET /api/scans/{scan_id}/report?format=html|json|pdf`. PDF generation uses
the declared ReportLab dependency. Scan records are in memory and disappear
when the backend restarts.

The backend provides seven fixed profiles: `quick_tcp`, `basic_tcp`, `full_tcp`,
`service_detection`, `comprehensive_tcp`, `udp_top_100`, and
`tcp_udp_common`. Their scopes range from 100 common TCP ports to all TCP

`full_tcp` and `comprehensive_tcp` use Nmap `-T4` timing and
`--max-retries 3` to reduce worst-case delays on unresponsive ports. This is a
performance/accuracy trade-off: less reliable networks may miss ports that
would have been detected with more retransmissions. The configured profile
timeouts remain hard limits; a timeout is reported as a failed scan. Their scopes range from 100 common TCP ports to all TCP
ports, light service detection, 100 common UDP ports, or combined common TCP
and UDP ports. UDP scans may require elevated privileges.

Profile-specific timeouts default to 60, 120, 900, 300, 1200, 600, and 600
seconds respectively. The environment variable
`NMAP_TIMEOUT_<PROFILE_ID_IN uppercase>` may override a timeout with a positive
integer up to the 1800-second hard maximum.

At most two scans execute concurrently by default. `MAX_CONCURRENT_SCANS`
configures the execution limit from 1 through 16, while `MAX_PENDING_SCANS`
configures total queue capacity (default 4, maximum 64). The API returns `429`
when that capacity is full. `GET /api/scans/{scan_id}` exposes Nmap progress
stage, percentage when reported, elapsed time, optional ETA, last update time,
and a human-readable message. Nmap progress percentages may be absent or
stage-relative; the UI uses an indeterminate indicator rather than inventing a
percentage.

While a scan is running, activity can be polled with
`GET /api/scans/{scan_id}/events?after=<sequence>`. Events are bounded,
sanitized messages from Nmap's normal output plus truthful backend lifecycle
events. The sequence cursor allows each scan's activity log to be tracked
independently; failed scans retain their partial log and do not receive a
completion event. Nmap normal output is streamed separately from the
machine-readable XML written to a unique temporary file, which is parsed only
after a successful process exit.

The frontend maintains an independent event cursor for every queued or running
scan. The Scan History page exposes these scans in an Active scans section and
opens a terminal-style activity view without stopping monitoring of the other
scans.
