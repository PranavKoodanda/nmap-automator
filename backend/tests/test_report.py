from datetime import datetime, timezone

from backend.app.reports.html_report import ReportData, generate_html_report
from backend.app.schemas.scan import (
    FindingResponse,
    PortResponse,
    ScanFindingsResponse,
    ScanPortsResponse,
    ScanResponse,
    ScanStatus,
    ScanSummary,
)
from backend.app.scanner.profiles import ScanProfile


def report_data(
    *,
    target: str = "192.0.2.10",
    findings: list[FindingResponse] | None = None,
    ports: list[PortResponse] | None = None,
) -> ReportData:
    created = datetime(2026, 10, 18, tzinfo=timezone.utc)
    scan = ScanResponse(
        scan_id="scan-123",
        target=target,
        profile=ScanProfile.SERVICE_DETECTION,
        status=ScanStatus.COMPLETED,
        created_at=created,
        completed_at=created,
        summary=ScanSummary(
            reported_ports=2,
            open_ports=1,
            closed_ports=1,
            filtered_ports=0,
            unavailable_state_ports=0,
        ),
    )
    port_response = ScanPortsResponse(
        scan_id=scan.scan_id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        ports=ports
        or [
            PortResponse(
                port=23,
                protocol="tcp",
                state="open",
                service="telnet",
                product=None,
                version=None,
                detection_method="probed",
                service_confidence=10,
            ),
            PortResponse(
                port=80,
                protocol="tcp",
                state="closed",
                service=None,
                product=None,
                version=None,
                detection_method=None,
                service_confidence=None,
            ),
        ],
    )
    finding_response = ScanFindingsResponse(
        scan_id=scan.scan_id,
        target=scan.target,
        profile=scan.profile,
        status=scan.status,
        findings=findings or [],
    )
    return ReportData(scan=scan, ports=port_response, findings=finding_response)


def test_report_renders_metrics_ports_findings_and_limitations() -> None:
    finding = FindingResponse(
        rule_id="service.telnet-exposed",
        title="Open Telnet service observed",
        severity="high",
        description="Identified service",
        evidence="Open tcp/23",
        risk_explanation="Cleartext risk",
        recommended_remediation="Disable Telnet",
        confidence="high",
        verification_status="requires_verification",
    )

    report = generate_html_report(
        report_data(findings=[finding]),
        generated_at=datetime(2026, 10, 18, 12, tzinfo=timezone.utc),
    )

    assert "Security Assessment Report" in report
    assert "Reported ports: 2" in report
    assert "Open: 1" in report
    assert "Closed: 1" in report
    assert "Findings: 1" in report
    assert "Open Telnet service observed" in report
    assert "Cleartext risk" in report
    assert "Disable Telnet" in report
    assert "requires_verification" in report
    assert "service_confidence" not in report
    assert "probed (10/10)" in report


def test_report_escapes_untrusted_text_and_handles_no_findings() -> None:
    report = generate_html_report(
        report_data(
            target="<script>alert('x')</script>",
            ports=[
                PortResponse(
                    port=443,
                    protocol="tcp",
                    state="open",
                    service="<img src=x>",
                    product="<bad>",
                    version=None,
                    detection_method=None,
                    service_confidence=None,
                )
            ],
        )
    )

    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in report
    assert "&lt;img src=x&gt;" in report
    assert "&lt;bad&gt;" in report
    assert "<script>" not in report
    assert "<img" not in report
    assert "No rule-based findings were generated." in report
    assert "does not prove that the target is secure" in report
