"""Bounded in-memory scan lifecycle management."""

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import threading
from uuid import uuid4

from backend.app.schemas.scan import (
    PortResponse,
    ScanPortsResponse,
    ScanResponse,
    ScanStatus,
    ScanSummary,
)
from backend.app.scanner.engine import ScanExecutionResult, run_scan
from backend.app.scanner.profiles import ScanProfile


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


class ScanManager:
    """Thread-safe manager with a bounded executor submission capacity."""

    def __init__(
        self,
        *,
        scanner: Scanner = run_scan,
        max_workers: int = 2,
        max_pending: int = 4,
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

    def get_ports(self, scan_id: str) -> ScanPortsResponse:
        with self._lock:
            record = self._records.get(scan_id)
            if record is None:
                raise ScanNotFoundError(scan_id)
            if record.status is not ScanStatus.COMPLETED or record.result is None:
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

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _execute(self, scan_id: str) -> None:
        with self._lock:
            record = self._records[scan_id]
            record.status = ScanStatus.RUNNING
        try:
            result = self._scanner(record.target, record.profile)
        except Exception as exc:
            with self._lock:
                record.status = ScanStatus.FAILED
                record.completed_at = datetime.now(timezone.utc)
                record.error = _sanitize_error(exc)
        else:
            with self._lock:
                record.status = ScanStatus.COMPLETED
                record.completed_at = datetime.now(timezone.utc)
                record.result = result
        finally:
            self._capacity.release()

    @staticmethod
    def _to_response(record: _ScanRecord) -> ScanResponse:
        summary = _summary(record.result) if record.result is not None else None
        return ScanResponse(
            scan_id=record.scan_id,
            target=record.target,
            profile=record.profile,
            status=record.status,
            created_at=record.created_at,
            completed_at=record.completed_at,
            summary=summary,
            error=record.error,
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


def _sanitize_error(error: Exception) -> str:
    message = str(error).strip().replace("\r", " ").replace("\n", " ")
    return message[:500] or "Scan failed."
