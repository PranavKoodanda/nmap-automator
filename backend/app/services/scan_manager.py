"""Bounded in-memory scan lifecycle management."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading
import inspect
import re
from uuid import uuid4

from backend.app.analyzer.rules import SecurityFinding, analyze_scan
from backend.app.reports.html_report import ReportData
from backend.app.schemas.scan import (
    FindingResponse,
    PortResponse,
    ScanFindingsResponse,
    ScanPortsResponse,
    ScanResponse,
    ScanProgress,
    ScanStatus,
    ScanSummary,
    ScanEventResponse,
    ScanEventsResponse,
)
from backend.app.scanner.engine import (
    NmapCancelledError,
    NmapTimeoutError,
    ProgressUpdate,
    ScanEvent,
    ScanExecutionResult,
    run_scan,
)
from backend.app.scanner.profiles import ScanProfile
from backend.app.scanner.parser import PortResult, ScanResult, ServiceMetadata


class ScanNotFoundError(LookupError):
    """Raised when a scan ID is not present."""


class ScanCapacityError(RuntimeError):
    """Raised when the bounded scan queue is full."""


class ScanNotReadyError(RuntimeError):
    """Raised when ports are requested before successful completion."""


Scanner = Callable[[str, ScanProfile], ScanExecutionResult]


@dataclass
class _ScanRecord:
    scan_id: str
    target: str
    profile: ScanProfile
    created_at: datetime
    status: ScanStatus = ScanStatus.QUEUED
    completed_at: datetime | None = None
    result: ScanExecutionResult | None = None
    error: str | None = None
    findings: tuple[SecurityFinding, ...] = ()
    started_at: datetime | None = None
    progress: ScanProgress = field(
        default_factory=lambda: ScanProgress(elapsed_seconds=0.0)
    )
    events: list[ScanEventResponse] = field(default_factory=list)
    next_event_sequence: int = 1
    cancel_event: threading.Event = field(default_factory=threading.Event)
    finished_event: threading.Event = field(default_factory=threading.Event)


class ScanManager:
    """Thread-safe manager with a bounded executor submission capacity."""

    def __init__(
        self,
        *,
        scanner: Scanner = run_scan,
        max_workers: int = 2,
        max_pending: int = 4,
        max_events: int = 200,
    ) -> None:
        if max_workers < 1 or max_pending < 1:
            raise ValueError("Worker and pending limits must be positive.")
        self._scanner = scanner
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="nmap-scan",
        )
        self._capacity = threading.BoundedSemaphore(max_pending)
        self._lock = threading.RLock()
        self._records: dict[str, _ScanRecord] = {}
        self._max_events = max_events

    @classmethod
    def from_environment(cls, *, scanner: Scanner = run_scan) -> "ScanManager":
        from backend.app.config import Settings

        settings = Settings.from_environment()
        return cls(
            scanner=scanner,
            max_workers=settings.max_concurrent_scans,
            max_pending=settings.max_pending_scans,
        )

    def submit(self, target: str, profile: ScanProfile) -> ScanResponse:
        if not self._capacity.acquire(blocking=False):
            raise ScanCapacityError("Scan queue capacity has been reached.")
        record = _ScanRecord(
            scan_id=str(uuid4()),
            target=target,
            profile=profile,
            created_at=datetime.now(timezone.utc),
        )
        with self._lock:
            self._records[record.scan_id] = record
        try:
            self._executor.submit(self._execute, record.scan_id)
        except RuntimeError as exc:
            with self._lock:
                self._records.pop(record.scan_id, None)
            self._capacity.release()
            raise ScanCapacityError("Scan workers are unavailable.") from exc
        return self._to_response(record)

    def get(self, scan_id: str) -> ScanResponse:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                raise ScanNotFoundError(scan_id)
            return self._to_response(record)

    def get_events(self, scan_id: str, after: int = 0) -> ScanEventsResponse:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                raise ScanNotFoundError(scan_id)
            events = [event for event in record.events if event.sequence > after]
            return ScanEventsResponse(
                scan_id=scan_id,
                events=events,
                next_sequence=record.next_event_sequence,
            )

    def stop(self, scan_id: str) -> ScanResponse:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                raise ScanNotFoundError(scan_id)
            wait_for_stop = record.status is ScanStatus.RUNNING
            if record.status is ScanStatus.QUEUED:
                record.cancel_event.set()
                record.status = ScanStatus.CANCELLED
                record.completed_at = datetime.now(timezone.utc)
                record.error = "Scan stopped by user."
                record.result = ScanExecutionResult(
                    target=record.target,
                    profile=record.profile,
                    scan=ScanResult(target=record.target, ports=()),
                    stderr="",
                    returncode=-1,
                )
                record.progress = _terminal_progress(record, record.error)
                self._append_event(record, "cancelled", record.error)
            elif record.status is ScanStatus.RUNNING:
                if not record.cancel_event.is_set():
                    record.cancel_event.set()
                    self._append_event(record, "info", "Stop requested; terminating Nmap.")
            finished_event = record.finished_event
            response = self._to_response(record)
        if wait_for_stop:
            finished_event.wait(timeout=5)
            with self._lock:
                record = self._records.get(scan_id)
                if record is None:
                    raise ScanNotFoundError(scan_id)
                response = self._to_response(record)
        return response

    def get_ports(self, scan_id: str) -> ScanPortsResponse:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                raise ScanNotFoundError(scan_id)
            if record.status not in {ScanStatus.COMPLETED, ScanStatus.CANCELLED} or record.result is None:
                raise ScanNotReadyError(record.status.value)
            result = record.result
            ports = [
                PortResponse(
                    port=port.port,
                    protocol=port.protocol,
                    state=port.state,
                    service=port.service.name,
                    product=port.service.product,
                    version=port.service.version,
                    detection_method=port.service.detection_method,
                    service_confidence=port.service.confidence,
                )
                for port in result.scan.ports
            ]
            return ScanPortsResponse(
                scan_id=record.scan_id,
                target=record.target,
                profile=record.profile,
                status=record.status,
                ports=ports,
            )

    def get_findings(self, scan_id: str) -> ScanFindingsResponse:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                raise ScanNotFoundError(scan_id)
            if record.status not in {ScanStatus.COMPLETED, ScanStatus.CANCELLED} or record.result is None:
                raise ScanNotReadyError(record.status.value)
            return ScanFindingsResponse(
                scan_id=record.scan_id,
                target=record.target,
                profile=record.profile,
                status=record.status,
                findings=[
                    FindingResponse(
                        rule_id=finding.rule_id,
                        title=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.evidence,
                        risk_explanation=finding.risk_explanation,
                        recommended_remediation=finding.recommended_remediation,
                        confidence=finding.confidence,
                        verification_status=finding.verification_status,
                    )
                    for finding in record.findings
                ],
            )

    def get_report_data(self, scan_id: str) -> ReportData:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                raise ScanNotFoundError(scan_id)
            if record.status not in {ScanStatus.COMPLETED, ScanStatus.CANCELLED} or record.result is None:
                raise ScanNotReadyError(record.status.value)
            return ReportData(
                scan=self._to_response(record),
                ports=self.get_ports(scan_id),
                findings=self.get_findings(scan_id),
                events=list(record.events),
            )

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _execute(self, scan_id: str) -> None:
        with self._lock:
            record = self._records[scan_id]
            if record.status is ScanStatus.CANCELLED:
                record.finished_event.set()
                self._capacity.release()
                return
            record.status = ScanStatus.RUNNING
            record.started_at = datetime.now(timezone.utc)
            record.progress = ScanProgress(
                stage="starting",
                elapsed_seconds=0.0,
                last_update_at=record.started_at,
                message="Starting Nmap.",
            )
            self._append_event(record, "info", "Nmap scan started.")
        try:
            result = self._invoke_scanner(record)
            with self._lock:
                if record.cancel_event.is_set():
                    record.status = ScanStatus.CANCELLED
                    record.completed_at = datetime.now(timezone.utc)
                    record.error = "Scan stopped by user."
                    record.result = _merge_discovered_ports(result, record.events)
                    record.findings = analyze_scan(record.result)
                    record.progress = _terminal_progress(record, record.error)
                    self._append_event(record, "cancelled", record.error)
                    return
                record.status = ScanStatus.COMPLETED
                record.completed_at = datetime.now(timezone.utc)
                record.progress = _terminal_progress(
                    record, "Nmap completed successfully."
                )
                record.result = result
                record.findings = analyze_scan(result)
                self._append_event(record, "completed", "Scan completed.")
        except NmapCancelledError as exc:
            with self._lock:
                record.status = ScanStatus.CANCELLED
                record.completed_at = datetime.now(timezone.utc)
                record.error = "Scan stopped by user."
                partial_result = getattr(exc, "partial_result", None)
                if partial_result is None:
                    partial_result = ScanExecutionResult(
                        target=record.target,
                        profile=record.profile,
                        scan=ScanResult(target=record.target, ports=()),
                        stderr="",
                        returncode=-1,
                    )
                record.result = _merge_discovered_ports(partial_result, record.events)
                record.findings = analyze_scan(record.result)
                record.progress = _terminal_progress(record, record.error)
                self._append_event(record, "cancelled", record.error)
        except Exception as exc:
            with self._lock:
                record.status = ScanStatus.FAILED
                record.completed_at = datetime.now(timezone.utc)
                record.progress = _terminal_progress(
                    record, "Scan failed before successful result processing."
                )
                message = _sanitize_error(exc)
                record.error = (
                    f"Scan {record.scan_id} timed out: {message}"
                    if isinstance(exc, NmapTimeoutError)
                    else message
                )
                self._append_event(
                    record,
                    "error",
                    f"Scan failed: {record.error}",
                )
        finally:
            record.finished_event.set()
            self._capacity.release()

    def _invoke_scanner(self, record: _ScanRecord) -> ScanExecutionResult:
        callback = lambda update: self._update_progress(record.scan_id, update)
        event_callback = lambda event: self._append_event(
            record, event.event_type, event.message
        )
        scanner = self._scanner
        try:
            parameters = inspect.signature(scanner).parameters
            supports_progress = (
                "progress_callback" in parameters
                or any(
                    parameter.kind
                    is inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters.values()
                )
            )
            supports_events = (
                "event_callback" in parameters
                or any(
                    parameter.kind
                    is inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters.values()
                )
            )
            supports_cancel = (
                "cancel_event" in parameters
                or any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values())
            )
        except (TypeError, ValueError):
            supports_progress = scanner is run_scan
            supports_cancel = scanner is run_scan
        if supports_progress or supports_events:
            try:
                kwargs: dict[str, Callable[..., object]] = {}
                if supports_progress:
                    kwargs["progress_callback"] = callback
                if supports_events:
                    kwargs["event_callback"] = event_callback
                if supports_cancel:
                    kwargs["cancel_event"] = self._records[record.scan_id].cancel_event
                return scanner(record.target, record.profile, **kwargs)
            except TypeError as exc:
                message = str(exc)
                if not any(name in message for name in ("event_callback", "progress_callback", "cancel_event")):
                    raise
                fallback_kwargs = dict(kwargs)
                if "event_callback" in message:
                    fallback_kwargs.pop("event_callback", None)
                if "progress_callback" in message:
                    fallback_kwargs.pop("progress_callback", None)
                if "cancel_event" in message:
                    fallback_kwargs.pop("cancel_event", None)
                return scanner(record.target, record.profile, **fallback_kwargs)
        return scanner(record.target, record.profile)

    def _update_progress(self, scan_id: str, update: ProgressUpdate) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            record = self._records.get(scan_id)
            if record is None or record.status is not ScanStatus.RUNNING:
                return
            record.progress = ScanProgress(
                stage=update.stage,
                percent=update.percent,
                elapsed_seconds=update.elapsed_seconds,
                estimated_remaining_seconds=update.estimated_remaining_seconds,
                last_update_at=now,
                message=update.message,
            )
            if not record.events or record.events[-1].message != update.message:
                self._append_event(record, "progress", update.message)

    def _append_event(
        self, record: _ScanRecord, event_type: str, message: str
    ) -> None:
        with self._lock:
            event = ScanEventResponse(
                sequence=record.next_event_sequence,
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                message=message[:240],
            )
            record.next_event_sequence += 1
            record.events.append(event)
            if len(record.events) > self._max_events:
                del record.events[: len(record.events) - self._max_events]

    @staticmethod
    def _to_response(record: _ScanRecord) -> ScanResponse:
        summary = _summary(record.result) if record.result is not None else None
        return ScanResponse(
            scan_id=record.scan_id,
            target=record.target,
            profile=record.profile,
            status=record.status,
            created_at=record.created_at,
            started_at=record.started_at,
            completed_at=record.completed_at,
            summary=summary,
            error=record.error,
            progress=_progress_response(record),
        )


def _summary(result: ScanExecutionResult) -> ScanSummary:
    counts = {state: 0 for state in ("open", "closed", "filtered")}
    unavailable = 0
    for port in result.scan.ports:
        if port.state in counts:
            counts[port.state] += 1
        else:
            unavailable += 1
    return ScanSummary(
        reported_ports=len(result.scan.ports),
        open_ports=counts["open"],
        closed_ports=counts["closed"],
        filtered_ports=counts["filtered"],
        unavailable_state_ports=unavailable,
    )


def _merge_discovered_ports(
    result: ScanExecutionResult,
    events: list[ScanEventResponse],
) -> ScanExecutionResult:
    """Keep open-port events as observations if partial XML has not flushed them."""

    ports = {(port.protocol, port.port): port for port in result.scan.ports}
    for event in events:
        if event.event_type != "port_discovered":
            continue
        match = re.search(r"\b(\d{1,5})/(tcp|udp)\b", event.message, re.IGNORECASE)
        if match is None:
            continue
        port_number = int(match.group(1))
        protocol = match.group(2).lower()
        if port_number > 65535:
            continue
        ports.setdefault(
            (protocol, port_number),
            PortResult(
                port=port_number,
                protocol=protocol,
                state="open",
                service=ServiceMetadata(),
            ),
        )
    if len(ports) == len(result.scan.ports):
        return result
    return ScanExecutionResult(
        target=result.target,
        profile=result.profile,
        scan=ScanResult(target=result.scan.target, ports=tuple(ports.values())),
        stderr=result.stderr,
        returncode=result.returncode,
    )


def _sanitize_error(error: Exception) -> str:
    message = str(error).strip().replace("\r", " ").replace("\n", " ")
    return message[:500] or "Scan failed."


def _progress_response(record: _ScanRecord) -> ScanProgress:
    progress = record.progress
    if record.status is ScanStatus.QUEUED:
        return progress
    if record.status is ScanStatus.RUNNING and record.started_at is not None:
        elapsed = max(
            0.0,
            (datetime.now(timezone.utc) - record.started_at).total_seconds(),
        )
        progress = progress.model_copy(update={"elapsed_seconds": round(elapsed, 3)})
    if record.status is not ScanStatus.RUNNING or progress.last_update_at is None:
        return progress
    if (
        datetime.now(timezone.utc) - progress.last_update_at
    ).total_seconds() > 15:
        return progress.model_copy(
            update={"message": "No new Nmap statistics recently."}
        )
    return progress


def _terminal_progress(record: _ScanRecord, message: str) -> ScanProgress:
    elapsed = 0.0
    if record.started_at is not None:
        elapsed = max(
            0.0,
            (datetime.now(timezone.utc) - record.started_at).total_seconds(),
        )
    return record.progress.model_copy(
        update={
            "stage": (
                None if record.progress.stage == "starting" else record.progress.stage
            ),
            "elapsed_seconds": round(elapsed, 3),
            "last_update_at": datetime.now(timezone.utc),
            "message": message,
        }
    )
