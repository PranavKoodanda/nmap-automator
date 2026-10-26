"""Self-contained HTML security assessment reports."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
import json
import re
from io import BytesIO

from backend.app.schemas.scan import (
    ScanFindingsResponse,
    ScanPortsResponse,
    ScanResponse,
    ScanEventResponse,
)
from backend.app.scanner.profiles import get_profile


@dataclass(frozen=True, slots=True)
class ReportData:
    """Completed or cancelled scan data used to render one report."""

    scan: ScanResponse
    ports: ScanPortsResponse
    findings: ScanFindingsResponse
    events: list[ScanEventResponse] = field(default_factory=list)


def generate_html_report(
    data: ReportData,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a completed or cancelled scan as a standalone HTML document."""

    _require_reportable(data)
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)

    scan = data.scan
    summary = scan.summary
    if summary is None:
        raise ValueError("Reportable scan is missing its summary.")
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
    event_rows = "".join(_event_row(event) for event in data.events)
    if not event_rows:
        event_rows = '<tr><td colspan="3">No terminal output was retained.</td></tr>'
    is_incomplete = scan.status.value == "cancelled"
    stopped_notice = (
        '<section class="incomplete-notice"><strong>Incomplete scan</strong>'
        '<p>This scan was stopped before its selected scope completed. The ports and output below are only observations captured before it stopped. Unscanned ports and services are unknown; no security conclusion can be drawn from their absence.</p></section>'
        if is_incomplete else ""
    )
    completion_label = "Stopped at" if is_incomplete else "Completion"
    elapsed_label = "Elapsed time" if is_incomplete else "Scan duration"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Assessment Report - {_text(scan.scan_id)}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ background: #f3f6fa; color: #263746; font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.55; margin: 0 auto; max-width: 1180px; padding: 2rem; }}
h1, h2 {{ color: #172b4d; }}
h1, h2, h3, p {{ margin-top: 0; }}
.report-header {{ background: linear-gradient(125deg, #102a43, #17516a); border-radius: .85rem; box-shadow: 0 14px 34px #102a431c; color: #fff; margin-bottom: 1.5rem; overflow: hidden; padding: 2.2rem; }}
.brand {{ color: #8ec5ff; font-size: .78rem; font-weight: 700; letter-spacing: .12em; margin-bottom: 1.5rem; text-transform: uppercase; }}
.report-header h1 {{ color: #fff; font-size: clamp(1.8rem, 4vw, 2.7rem); margin-bottom: .55rem; }}
.header-label {{ color: #b8d8f8; font-size: .72rem; font-weight: 700; letter-spacing: .08em; margin-bottom: .25rem; text-transform: uppercase; }}
.target-value {{ color: #fff; font-size: clamp(1.35rem, 3vw, 2rem); font-weight: 700; overflow-wrap: anywhere; }}
.header-summary {{ align-items: end; display: flex; flex-wrap: wrap; gap: 1.25rem 2rem; justify-content: space-between; }}
.profile-value {{ color: #e3effc; font-size: 1rem; }}
.status {{ border: 1px solid #8ec5ff; border-radius: 999px; color: #fff; display: inline-block; font-size: .78rem; font-weight: 700; letter-spacing: .06em; padding: .35rem .7rem; text-transform: uppercase; }}
.status-completed {{ background: #176b4d; border-color: #8ee0bd; }}
.status-running, .status-queued {{ background: #245886; }}
.status-failed {{ background: #8a2f3d; border-color: #ffb4bd; }}
.status-cancelled {{ background: #855600; border-color: #ffd479; }}
.scan-id {{ border-top: 1px solid #315475; color: #d7e8f8; font-family: Consolas, monospace; font-size: .86rem; margin-top: 1.5rem; overflow-wrap: anywhere; padding-top: .8rem; user-select: text; }}
.metadata-cards {{ display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin-top: 1.5rem; }}
.metadata-card {{ background: #fff; border: 1px solid #d7dee8; border-radius: .55rem; color: #172b4d; min-height: 5.2rem; padding: .85rem; }}
.metadata-card .header-label {{ color: #60758a; }}
.metadata-value {{ font-size: .95rem; font-weight: 700; overflow-wrap: anywhere; }}
main > section {{ background: #fff; border: 1px solid #dce4ec; border-radius: .7rem; box-shadow: 0 4px 14px #102a4309; margin: 1.1rem 0; padding: 1.35rem; }}
main h2 {{ border-bottom: 1px solid #e6edf3; font-size: 1.15rem; margin-bottom: 1rem; padding-bottom: .7rem; }}
table {{ border-collapse: collapse; margin: 1rem 0 .4rem; width: 100%; }}
th, td {{ border-bottom: 1px solid #e0e7ee; padding: .7rem .65rem; text-align: left; vertical-align: top; }}
th {{ background: #eff4f8; color: #35546b; font-size: .78rem; letter-spacing: .04em; text-transform: uppercase; }}
tbody tr:nth-child(even) {{ background: #f8fafc; }}
.metric {{ background: #f6f9fc; border: 1px solid #dce5ed; border-radius: .5rem; color: #263e52; display: inline-block; margin: .25rem; min-width: 8rem; padding: .8rem 1rem; }}
.finding {{ background: #fbfcfe; border: 1px solid #dce5ed; border-radius: .55rem; margin: 1rem 0; padding: 1.1rem 1.2rem; }}
.finding p {{ margin-bottom: .55rem; }}
.incomplete-notice {{ background: #fff7e6; border: 1px solid #e6bd69; border-left: .35rem solid #bf7600; border-radius: .55rem; color: #543b15; margin: 1rem 0; padding: 1.1rem 1.25rem; }}
.incomplete-notice p {{ margin: .4rem 0 0; }}
.muted {{ color: #60758a; }}
.severity-high {{ border-left: .35rem solid #b42318; }}
.severity-medium {{ border-left: .35rem solid #b54708; }}
.severity-low {{ border-left: .35rem solid #1570ef; }}
@media (max-width: 760px) {{ body {{ padding: .8rem; }} .metadata-cards {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
@media (max-width: 430px) {{ .metadata-cards {{ grid-template-columns: 1fr; }} }}
@media print {{ body {{ background: #fff; margin: 0; padding: 0; }} .report-header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; border-radius: 0; }} .metadata-card {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<header class="report-header">
<div class="brand">Nmap Automator</div>
<div class="header-summary">
<div>
<h1>{'Partial Scan Report' if is_incomplete else 'Security Assessment Report'}</h1>
<div class="header-label">Scanned target</div>
<div class="target-value">{_text(scan.target)}</div>
</div>
<div>
<div class="header-label">Status</div>
<div class="status status-{_text(scan.status.value)}">{_text(_status_label(scan.status.value))}</div>
</div>
</div>
<div class="header-summary" style="margin-top: 1.35rem;">
<div><div class="header-label">Scan profile</div><div class="profile-value">{_text(_profile_label(scan.profile.value))} <span class="profile-id">({_text(scan.profile.value)})</span></div></div>
</div>
<div class="scan-id"><span class="header-label">Scan ID</span><br>{_text(scan.scan_id)}</div>
</header>
<section class="metadata-cards" aria-label="Scan timing metadata">
<div class="metadata-card"><div class="header-label">Scan start</div><div class="metadata-value">{_timestamp(scan.started_at or scan.created_at)}</div></div>
<div class="metadata-card"><div class="header-label">{completion_label}</div><div class="metadata-value">{_timestamp(scan.completed_at)}</div></div>
<div class="metadata-card"><div class="header-label">{elapsed_label}</div><div class="metadata-value">{_duration(scan.started_at or scan.created_at, scan.completed_at)}</div></div>
<div class="metadata-card"><div class="header-label">Report generated</div><div class="metadata-value">{_timestamp(generated_at)}</div></div>
<div class="metadata-card"><div class="header-label">Progress at end</div><div class="metadata-value">{_text(f'{scan.progress.percent:g}%' if scan.progress.percent is not None else 'Unavailable')}</div></div>
</section>
<main>
{stopped_notice}
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
<section><h2>Captured Nmap output</h2><p class="muted">Retained terminal events recorded during this scan.</p>
<table><thead><tr><th>Time (UTC)</th><th>Type</th><th>Output</th></tr></thead><tbody>{event_rows}</tbody></table>
</section>
<section><h2>Methodology and limitations</h2>
<p>This report reflects the selected <strong>{_text(_profile_label(scan.profile.value))}</strong> (<code>{_text(scan.profile.value)}</code>) and its reported scope.</p>
<p><strong>Protocols scanned:</strong> {_text(_profile_scope(scan.profile.value)["protocols"])}<br>
<strong>Port selection:</strong> {_text(_profile_scope(scan.profile.value)["ports"])}</p>
<ul>
<li>An open port alone does not prove a vulnerability.</li>
<li>Service detection is evidence, not conclusive proof of service identity or vulnerability.</li>
<li>Findings marked <code>requires_verification</code> need additional validation.</li>
<li>This report does not establish external reachability unless separately verified.</li>
{('<li>The scan ended early. A missing port or service means it was not observed before cancellation, not that it is closed.</li>' if is_incomplete else '')}
</ul>
{("<p>No rule-based findings were generated; this does not prove that the target is secure.</p>" if not data.findings.findings else "")}
</section>
</main>
</body>
</html>
"""


def safe_report_filename(scan_id: str) -> str:
    return safe_report_filename_for(scan_id, "html")


def safe_report_filename_for(scan_id: str, extension: str) -> str:
    safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", scan_id)
    return f"security-assessment-{safe_id}.{extension}"


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


def _event_row(event: ScanEventResponse) -> str:
    return (
        "<tr>"
        f"<td>{_timestamp(event.timestamp)}</td>"
        f"<td>{_text(event.event_type.replace('_', ' '))}</td>"
        f"<td>{_text(event.message)}</td>"
        "</tr>"
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
    if value is None:
        return _text(None)
    utc_value = value.astimezone(timezone.utc)
    return _text(utc_value.strftime("%d %b %Y, %H:%M:%S UTC"))


def _duration(start: datetime | None, end: datetime | None) -> str:
    if start is None or end is None or end < start:
        return _text(None)
    total_seconds = int((end - start).total_seconds())
    minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return _text(f"{hours}h {minutes}m {seconds}s")
    if minutes:
        return _text(f"{minutes}m {seconds}s")
    return _text(f"{seconds}s")


def _profile_label(profile: str) -> str:
    labels = {
        "quick_tcp": "Quick TCP scan",
        "basic_tcp": "Basic TCP scan",
        "full_tcp": "Full TCP scan",
        "service_detection": "Service detection scan",
        "comprehensive_tcp": "Comprehensive TCP scan",
        "udp_top_100": "UDP top ports scan",
        "tcp_udp_common": "Common TCP + UDP scan",
    }
    if profile in labels:
        return labels[profile]
    try:
        return get_profile(profile).description.split(".")[0]
    except ValueError:
        return profile.replace("_", " ").replace("-", " ").title()


def _profile_scope(profile: str) -> dict[str, str]:
    scopes = {
        "quick_tcp": {"protocols": "TCP", "ports": "100 most common TCP ports (-F)"},
        "basic_tcp": {"protocols": "TCP", "ports": "TCP ports 1-1000"},
        "full_tcp": {"protocols": "TCP", "ports": "TCP ports 1-65535"},
        "service_detection": {"protocols": "TCP", "ports": "TCP ports 1-1000"},
        "comprehensive_tcp": {"protocols": "TCP", "ports": "TCP ports 1-65535"},
        "udp_top_100": {"protocols": "UDP", "ports": "100 most common UDP ports (-F)"},
        "tcp_udp_common": {"protocols": "TCP and UDP", "ports": "100 most common TCP and UDP ports (-F)"},
    }
    return scopes.get(
        profile,
        {"protocols": "Unavailable", "ports": "Unavailable"},
    )


def _status_label(status: str) -> str:
    return status.replace("_", " ").title()


def _report_payload(data: ReportData, generated_at: datetime | None = None) -> dict:
    _require_reportable(data)
    generated = generated_at or datetime.now(timezone.utc)
    summary = data.scan.summary
    if summary is None:
        raise ValueError("Reportable scan is missing its summary.")
    finding_counts = {
        severity: sum(
            finding.severity.value == severity for finding in data.findings.findings
        )
        for severity in ("high", "medium", "low")
    }
    return {
        "schema_version": "1.1",
        "report_generated_at": generated.isoformat(),
        "scan": {
            "scan_id": data.scan.scan_id,
            "target": data.scan.target,
            "profile": data.scan.profile.value,
            "status": data.scan.status.value,
            "created_at": data.scan.created_at.isoformat(),
            "started_at": data.scan.started_at.isoformat() if data.scan.started_at else None,
            "completed_at": data.scan.completed_at.isoformat()
            if data.scan.completed_at
            else None,
            "duration_seconds": (
                (data.scan.completed_at - (data.scan.started_at or data.scan.created_at)).total_seconds()
                if data.scan.completed_at
                else None
            ),
            "profile_id": data.scan.profile.value,
            "profile_name": _profile_label(data.scan.profile.value),
            "scope": _profile_scope(data.scan.profile.value),
        },
        "summary": {
            "reported_ports": summary.reported_ports,
            "open_ports": summary.open_ports,
            "closed_ports": summary.closed_ports,
            "filtered_ports": summary.filtered_ports,
            "unavailable_state_ports": summary.unavailable_state_ports,
            "finding_counts_by_severity": finding_counts,
        },
        "progress_at_end": {
            "percent": data.scan.progress.percent,
            "message": data.scan.progress.message,
            "elapsed_seconds": data.scan.progress.elapsed_seconds,
        },
        "ports": [
            {
                "port": port.port,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                "product": port.product,
                "version": port.version,
                "detection_method": port.detection_method,
                "service_confidence": port.service_confidence,
            }
            for port in data.ports.ports
        ],
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.value,
                "description": finding.description,
                "evidence": finding.evidence,
                "risk_explanation": finding.risk_explanation,
                "recommended_remediation": finding.recommended_remediation,
                "confidence": finding.confidence,
                "verification_status": finding.verification_status.value,
            }
            for finding in data.findings.findings
        ],
        "limitations": [
            "The report reflects only the selected scan profile and reported scope.",
            "An open port alone does not prove a vulnerability.",
            "Service detection is evidence, not conclusive proof.",
            "External reachability was not established by this scan.",
            *(["The scan was cancelled before the selected scope completed; unobserved ports and services are unknown."] if data.scan.status.value == "cancelled" else []),
        ],
        "terminal_events": [
            {"timestamp": event.timestamp.isoformat(), "event_type": event.event_type, "message": event.message}
            for event in data.events
        ],
    }


def _require_reportable(data: ReportData) -> None:
    if data.scan.status.value not in {"completed", "cancelled"}:
        raise ValueError("Reports are available only for completed or cancelled scans.")


def generate_json_report(
    data: ReportData,
    *,
    generated_at: datetime | None = None,
) -> str:
    return json.dumps(_report_payload(data, generated_at), indent=2) + "\n"


def generate_pdf_report(
    data: ReportData,
    *,
    generated_at: datetime | None = None,
) -> bytes:
    """Create a styled, paginated PDF for completed or cancelled scans."""

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    payload = _report_payload(data, generated_at)
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="Security Assessment Report",
        author="Nmap Automator",
    )
    styles = getSampleStyleSheet()
    navy = colors.HexColor("#102a43")
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=23, leading=27, textColor=navy, spaceAfter=8))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10, textColor=colors.HexColor("#526777")))
    styles.add(ParagraphStyle(name="Detail", parent=styles["BodyText"], fontSize=9, leading=13, spaceAfter=4))
    styles.add(ParagraphStyle(name="Notice", parent=styles["BodyText"], fontSize=9, leading=13, textColor=colors.HexColor("#573b10")))
    is_incomplete = payload["scan"]["status"] == "cancelled"
    story = [
        Paragraph("Partial Scan Report" if is_incomplete else "Security Assessment Report", styles["ReportTitle"]),
        Paragraph(f"{_text(payload['scan']['status']).upper()} &nbsp; | &nbsp; {_text(payload['scan']['target'])}", styles["Heading2"]),
        Paragraph(f"Scan ID: {_text(payload['scan']['scan_id'])}", styles["Small"]),
        Paragraph(
            f"Profile: {_text(payload['scan']['profile_name'])} "
            f"({_text(payload['scan']['profile_id'])})",
            styles["BodyText"],
        ),
        Paragraph(
            f"Protocols: {_text(payload['scan']['scope']['protocols'])}; "
            f"Port selection: {_text(payload['scan']['scope']['ports'])}",
            styles["Small"],
        ),
        Paragraph(f"Generated: {_text(payload['report_generated_at'])}", styles["Small"]),
        Spacer(1, 8),
    ]
    status_table = Table([["SCAN STATUS", _text(payload["scan"]["status"]).upper()]], colWidths=[38 * mm, 48 * mm])
    status_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), navy),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#a65c00") if is_incomplete else colors.HexColor("#16704d")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([status_table, Spacer(1, 12)])
    timeline = Table([
        ["STARTED", "STOPPED" if is_incomplete else "COMPLETED", "ELAPSED", "PROGRESS"],
        [
            _pdf_text(payload["scan"]["started_at"] or payload["scan"]["created_at"]),
            _pdf_text(payload["scan"]["completed_at"]),
            f"{payload['scan']['duration_seconds']:.1f} sec" if payload["scan"]["duration_seconds"] is not None else "Unavailable",
            f"{payload['progress_at_end']['percent']:g}%" if payload["progress_at_end"]["percent"] is not None else "Unavailable",
        ],
    ], colWidths=[46 * mm, 46 * mm, 38 * mm, 38 * mm])
    timeline.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf0f5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#35546b")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7),
        ("FONTSIZE", (0, 1), (-1, 1), 7),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d4dee6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.extend([timeline, Spacer(1, 12)])
    if is_incomplete:
        notice = Table([[Paragraph(
            "<b>Incomplete scan</b><br/>This scan stopped before its selected scope completed. "
            "Ports and output below are only observations captured before it stopped. "
            "Unscanned ports and services are unknown; their absence is not evidence that they are closed.",
            styles["Notice"],
        )]], colWidths=[178 * mm])
        notice.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff7e6")),
            ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#e1b85d")),
            ("LINEBEFORE", (0, 0), (0, 0), 4, colors.HexColor("#bf7600")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ]))
        story.extend([notice, Spacer(1, 10)])
    story.extend([
        Paragraph("Executive summary", styles["Heading2"]),
    ])
    summary = payload["summary"]
    metrics = [
        ["Reported", "Open", "Closed", "Filtered", "Findings"],
        [
            str(summary["reported_ports"]),
            str(summary["open_ports"]),
            str(summary["closed_ports"]),
            str(summary["filtered_ports"]),
            str(sum(summary["finding_counts_by_severity"].values())),
        ],
    ]
    table = Table(metrics, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#eff4f8")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d4dee6")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([table, Spacer(1, 10), Paragraph("Port and service inventory", styles["Heading2"])])
    port_rows = [["Port", "Protocol", "State", "Service", "Product / version", "Detection"]]
    port_rows.extend([
        [
            str(port["port"]),
            str(port["protocol"]),
            str(port["state"] or "Unavailable"),
            str(port["service"] or "Unavailable"),
            Paragraph(
                _pdf_text(
                    f"{port['product'] or 'Unavailable'} / "
                    f"{port['version'] or 'Unavailable'}"
                ),
                styles["Small"],
            ),
            Paragraph(
                _pdf_text(
                    f"{port['detection_method'] or 'Unavailable'}"
                    + (
                        f" ({port['service_confidence']}/10)"
                        if port["service_confidence"] is not None
                        else ""
                    )
                ),
                styles["Small"],
            ),
        ]
        for port in payload["ports"]
    ])
    ports_table = Table(
        port_rows,
        repeatRows=1,
        colWidths=[18 * mm, 22 * mm, 22 * mm, 30 * mm, 50 * mm, 36 * mm],
    )
    ports_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf0f5")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d4dee6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
    ]))
    story.extend([ports_table, Spacer(1, 10), Paragraph("Security findings", styles["Heading2"])])
    if not payload["findings"]:
        story.append(Paragraph("No rule-based findings were generated; this does not prove that the target is secure.", styles["BodyText"]))
    for finding in payload["findings"]:
        story.extend([
            Paragraph(f"{_text(finding['severity']).upper()}: {_text(finding['title'])}", styles["Heading3"]),
            Paragraph(f"<b>Rule:</b> {_text(finding['rule_id'])}", styles["Small"]),
            Paragraph(f"<b>Description:</b> {_text(finding['description'])}", styles["Detail"]),
            Paragraph(f"<b>Evidence:</b> {_text(finding['evidence'])}", styles["Detail"]),
            Paragraph(f"<b>Risk:</b> {_text(finding['risk_explanation'])}", styles["Detail"]),
            Paragraph(f"<b>Recommended action:</b> {_text(finding['recommended_remediation'])}", styles["Detail"]),
            Paragraph(f"<b>Confidence:</b> {_text(finding['confidence'])} &nbsp; <b>Verification:</b> {_text(finding['verification_status'])}", styles["Small"]),
            Spacer(1, 8),
        ])
    story.append(Paragraph("Captured Nmap output", styles["Heading2"]))
    terminal_rows = [["Time (UTC)", "Type", "Output"]]
    terminal_rows.extend([
        [Paragraph(_pdf_text(event["timestamp"]), styles["Small"]),
         Paragraph(_pdf_text(event["event_type"].replace("_", " ")), styles["Small"]),
         Paragraph(_pdf_text(event["message"]), styles["Small"])]
        for event in payload["terminal_events"]
    ] or [["—", "—", "No terminal output was retained."]])
    terminal_table = Table(terminal_rows, repeatRows=1, colWidths=[38 * mm, 30 * mm, 110 * mm])
    terminal_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d4dee6")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f9fc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.extend([terminal_table, Spacer(1, 10)])
    story.extend([
        Paragraph("Methodology and limitations", styles["Heading2"]),
        Paragraph("An open port alone does not prove a vulnerability. Service detection is evidence, not conclusive proof. External reachability was not established by this scan.", styles["Small"]),
        Paragraph("The scan ended early; unobserved ports and services are unknown." if is_incomplete else "This report reflects only the selected scan profile and reported scope.", styles["Small"]),
    ])
    document.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
    return buffer.getvalue()


def _pdf_text(value: object) -> str:
    return escape("Unavailable" if value is None else str(value))


def _pdf_footer(canvas: object, document: object) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm

    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColorRGB(0.35, 0.35, 0.35)
    canvas.drawString(16 * mm, 10 * mm, "Nmap Automator security assessment")
    canvas.drawRightString(
        A4[0] - 16 * mm,
        10 * mm,
        f"Page {document.page}",
    )
    canvas.restoreState()
