from backend.app.analyzer.rules import (
    FindingSeverity,
    VerificationStatus,
    analyze_scan,
)
from backend.app.scanner.engine import ScanExecutionResult
from backend.app.scanner.parser import PortResult, ScanResult, ServiceMetadata
from backend.app.scanner.profiles import ScanProfile


def execution(ports: tuple[PortResult, ...]) -> ScanExecutionResult:
    return ScanExecutionResult(
        target="127.0.0.1",
        profile=ScanProfile.BASIC_TCP,
        scan=ScanResult(target="127.0.0.1", ports=ports),
        stderr="",
        returncode=0,
    )


def test_telnet_rule_matches_open_identified_service() -> None:
    findings = analyze_scan(
        execution(
            (
                PortResult(
                    23,
                    "tcp",
                    "open",
                    ServiceMetadata(name="telnet", detection_method="probed", confidence=10),
                ),
            )
        )
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "service.telnet-exposed"
    assert findings[0].severity is FindingSeverity.HIGH
    assert findings[0].verification_status is VerificationStatus.REQUIRES_VERIFICATION
    assert "tcp/23" in findings[0].evidence
    assert "external exposure" not in findings[0].evidence


def test_rules_do_not_match_closed_unknown_or_missing_service() -> None:
    findings = analyze_scan(
        execution(
            (
                PortResult(23, "tcp", "closed", ServiceMetadata(name="telnet", detection_method="probed", confidence=10)),
                PortResult(21, "tcp", "open", ServiceMetadata()),
                PortResult(3389, "tcp", None, ServiceMetadata(name="rdp", detection_method="probed", confidence=10)),
                PortResult(9999, "tcp", "open", ServiceMetadata(name="ftp", detection_method="probed")),
            )
        )
    )

    assert findings == ()


def test_ftp_and_remote_admin_rules_have_consistent_fields() -> None:
    findings = analyze_scan(
        execution(
            (
                PortResult(21, "tcp", "open", ServiceMetadata(name="ftp", detection_method="probed", confidence=7)),
                PortResult(3389, "tcp", "open", ServiceMetadata(name="rdp", detection_method="probed", confidence=8)),
            )
        )
    )

    assert {finding.rule_id for finding in findings} == {
        "service.ftp-exposed",
        "service.remote-admin-exposed",
    }
    assert all(finding.title for finding in findings)
    assert all(finding.description for finding in findings)
    assert all(finding.evidence for finding in findings)
    assert all(finding.recommended_remediation for finding in findings)
    assert all(finding.severity in FindingSeverity for finding in findings)
    assert {finding.confidence for finding in findings} == {"medium"}


def test_inferred_or_ambiguous_services_do_not_create_findings() -> None:
    findings = analyze_scan(
        execution(
            (
                PortResult(
                    23,
                    "tcp",
                    "open",
                    ServiceMetadata(name="telnet", detection_method="table", confidence=10),
                ),
                PortResult(
                    21,
                    "tcp",
                    "open",
                    ServiceMetadata(name="ftp", detection_method=None, confidence=10),
                ),
                PortResult(
                    3389,
                    "tcp",
                    "open",
                    ServiceMetadata(name="rdp", detection_method="unknown", confidence=10),
                ),
            )
        )
    )

    assert findings == ()
