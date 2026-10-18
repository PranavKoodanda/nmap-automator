"""Self-contained HTML security assessment reports."""

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
import re

from backend.app.schemas.scan import (
    ScanFindingsResponse,
    ScanPortsResponse,
    ScanResponse,
)


@dataclass(frozen=True, slots=True)
class ReportData:
    """Completed scan data used to render one report."""

    scan: ScanResponse
    ports: ScanPortsResponse
    findings: ScanFindingsResponse


def generate_html_report(
    data: ReportData,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a completed scan record as a standalone, escaped HTML document."""

    if data.scan.status.value != "completed":
        raise ValueError("Reports can only be generated for completed scans.")
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)

    scan = data.scan
    summary = scan.summary
    if summary is None:
        raise ValueError("Completed scan is missing its summary.")
    severity_counts = {
        severity: sum(
            finding.severity.value == severity for finding in data.findings.findings
        )
        for severity in ("high", "medium", "low")
    }

    port_rows = "".join(_port_row(port) for port in data.ports.ports)
    finding_rows = "".join(_finding_section(finding) for finding in data.findings.findings)
    if not finding_rows:
        finding_rows = "<p>No rule-based findings were generated.</p>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report - {_text(scan.scan_id)}</title>
<style>
body {{ color: #202124; font-family: Arial, sans-serif; line-height: 1.45; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; }}
h1, h2 {{ color: #172b4d; }}
table {{ border-collapse: collapse; margin: 1rem 0 2rem; width: 100%; }}
th, td {{ border: 1px solid #c8ccd1; padding: .5rem; text-align: left; vertical-align: top; }}
th {{ background: #eef1f5; }}
.metric {{ display: inline-block; border: 1px solid #c8ccd1; margin: .25rem; padding: .6rem 1rem; }}
.finding {{ border: 1px solid #c8ccd1; margin: 1rem 0; padding: 1rem; }}
.severity-high {{ border-left: .35rem solid #b42318; }}
.severity-medium {{ border-left: .35rem solid #b54708; }}
.severity-low {{ border-left: .35rem solid #1570ef; }}
@media print {{ body {{ margin: 0; }} }}
</style>
</head>
<body>
<header>
<h1>Security Assessment Report</h1>
<dl>
<dt>Scan ID</dt><dd>{_text(scan.scan_id)}</dd>
<dt>Target</dt><dd>{_text(scan.target)}</dd>
<dt>Profile</dt><dd>{_text(scan.profile.value)}</dd>
<dt>Created</dt><dd>{_timestamp(scan.created_at)}</dd>
<dt>Completed</dt><dd>{_timestamp(scan.completed_at)}</dd>
<dt>Report generated</dt><dd>{_timestamp(generated_at)}</dd>
</dl>
</header>
<main>
<section><h2>Executive summary</h2>
<div class="metric">Reported ports: {_number(summary.reported_ports)}</div>
<div class="metric">Open: {_number(summary.open_ports)}</div>
<div class="metric">Closed: {_number(summary.closed_ports)}</div>
<div class="metric">Filtered: {_number(summary.filtered_ports)}</div>
<div class="metric">State unavailable: {_number(summary.unavailable_state_ports)}</div>
<div class="metric">Findings: {_number(len(data.findings.findings))}</div>
<div class="metric">High: {_number(severity_counts["high"])}</div>
<div class="metric">Medium: {_number(severity_counts["medium"])}</div>
<div class="metric">Low: {_number(severity_counts["low"])}</div>
</section>
<section><h2>Port and service inventory</h2>
<table><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Detection</th></tr></thead>
<tbody>{port_rows or '<tr><td colspan="7">No ports were reported.</td></tr>'}</tbody></table>
</section>
<section><h2>Security findings</h2>{finding_rows}</section>
<section><h2>Methodology and limitations</h2>
<p>This report reflects the selected <strong>{_text(scan.profile.value)}</strong> scan profile and its reported scope.</p>
<ul>
<li>An open port alone does not prove a vulnerability.</li>
<li>Service detection is evidence, not conclusive proof of service identity or vulnerability.</li>
<li>Findings marked <code>requires_verification</code> need additional validation.</li>
<li>This report does not establish external reachability unless separately verified.</li>
</ul>
{("<p>No rule-based findings were generated; this does not prove that the target is secure.</p>" if not data.findings.findings else "")}
</section>
</main>
</body>
</html>
"""


def safe_report_filename(scan_id: str) -> str:
    safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", scan_id)
    return f"scan-{safe_id}.html"


def _port_row(port: object) -> str:
    return (
        "<tr>"
        f"<td>{_text(port.port)}</td><td>{_text(port.protocol)}</td>"
        f"<td>{_text(port.state)}</td><td>{_text(port.service)}</td>"
        f"<td>{_text(port.product)}</td><td>{_text(port.version)}</td>"
        f"<td>{_detection(port.detection_method, port.service_confidence)}</td>"
        "</tr>"
    )


def _finding_section(finding: object) -> str:
    severity = _text(finding.severity.value)
    return (
        f'<article class="finding severity-{severity}">'
        f"<h3>{_text(finding.title)}</h3>"
        f"<p><strong>Rule:</strong> {_text(finding.rule_id)}</p>"
        f"<p><strong>Severity:</strong> {severity}</p>"
        f"<p><strong>Description:</strong> {_text(finding.description)}</p>"
        f"<p><strong>Evidence:</strong> {_text(finding.evidence)}</p>"
        f"<p><strong>Risk:</strong> {_text(finding.risk_explanation)}</p>"
        f"<p><strong>Remediation:</strong> {_text(finding.recommended_remediation)}</p>"
        f"<p><strong>Confidence:</strong> {_text(finding.confidence)}</p>"
        f"<p><strong>Verification:</strong> {_text(finding.verification_status.value)}</p>"
        "</article>"
    )


def _detection(method: str | None, confidence: int | None) -> str:
    if method is None and confidence is None:
        return "Unavailable"
    return f"{method or 'Unavailable'} ({confidence}/10)" if confidence is not None else str(method)


def _text(value: object) -> str:
    return escape("Unavailable" if value is None else str(value))


def _number(value: int) -> str:
    return str(value)


def _timestamp(value: datetime | None) -> str:
    return _text(value.isoformat() if value is not None else None)
