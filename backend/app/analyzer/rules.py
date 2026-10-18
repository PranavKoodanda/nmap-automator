"""Transparent, evidence-based security analysis rules."""

from dataclasses import dataclass
from enum import StrEnum

from backend.app.scanner.engine import ScanExecutionResult


class FindingSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class VerificationStatus(StrEnum):
    OBSERVED = "observed"
    REQUIRES_VERIFICATION = "requires_verification"


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    """A rule-based finding supported by reported scan evidence."""

    rule_id: str
    title: str
    severity: FindingSeverity
    description: str
    evidence: str
    risk_explanation: str
    recommended_remediation: str
    confidence: str
    verification_status: VerificationStatus


def analyze_scan(result: ScanExecutionResult) -> tuple[SecurityFinding, ...]:
    """Apply all rules to a completed scan result.

    Rules intentionally require an open state and a sufficiently confident
    actively probed service. Port-table inference, ambiguous methods, missing
    confidence, and port numbers without service evidence are not findings.
    """

    findings: list[SecurityFinding] = []
    for port in result.scan.ports:
        if (
            port.state != "open"
            or not port.service.name
            or port.service.detection_method != "probed"
            or port.service.confidence is None
            or port.service.confidence < 7
        ):
            continue
        service = port.service.name.lower()
        if service == "telnet":
            findings.append(
                _finding(
                    rule_id="service.telnet-exposed",
                    title="Open Telnet service observed",
                    severity=FindingSeverity.HIGH,
                    service=port.service.name,
                    port=port.port,
                    detection_confidence=port.service.confidence,
                    description="Nmap actively probed and identified an open Telnet service.",
                    risk_explanation=(
                        "Telnet commonly transmits credentials and session data "
                        "without transport encryption."
                    ),
                    remediation="Disable Telnet or replace it with an approved encrypted remote-access protocol.",
                )
            )
        elif service == "ftp":
            findings.append(
                _finding(
                    rule_id="service.ftp-exposed",
                    title="Open FTP service observed",
                    severity=FindingSeverity.MEDIUM,
                    service=port.service.name,
                    port=port.port,
                    detection_confidence=port.service.confidence,
                    description="Nmap actively probed and identified an open FTP service.",
                    risk_explanation=(
                        "Traditional FTP may expose credentials and transferred "
                        "data unless protected by an appropriate secure variant."
                    ),
                    remediation="Disable FTP or migrate to SFTP/FTPS with encrypted authentication and transfers.",
                )
            )
        elif service in {"rdp", "ms-wbt-server", "vnc"}:
            findings.append(
                _finding(
                    rule_id="service.remote-admin-exposed",
                    title="Open remote administration service observed",
                    severity=FindingSeverity.MEDIUM,
                    service=port.service.name,
                    port=port.port,
                    detection_confidence=port.service.confidence,
                    description="Nmap actively probed and identified an open remote administration service.",
                    risk_explanation=(
                        "Remote administration services increase attack surface "
                        "and should not be reachable from untrusted networks."
                    ),
                    remediation=(
                        "Restrict access to trusted administration networks, require strong "
                        "authentication, and verify patching and logging."
                    ),
                )
            )
    return tuple(findings)


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: FindingSeverity,
    service: str,
    port: int,
    detection_confidence: int,
    description: str,
    risk_explanation: str,
    remediation: str,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        evidence=(
            f"Open tcp/{port}; Nmap actively probed service name: {service}; "
            "network exposure context was not established."
        ),
        risk_explanation=risk_explanation,
        recommended_remediation=remediation,
        confidence="high" if detection_confidence >= 9 else "medium",
        verification_status=VerificationStatus.REQUIRES_VERIFICATION,
    )
