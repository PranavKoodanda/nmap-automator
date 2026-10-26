"""Capability-protected scan endpoints for public targets."""

import ipaddress
import socket

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from backend.app.auth import Capability, allow_rate_attempt, require_capability
from backend.app.config import Settings
from backend.app.reports.html_report import (
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
    safe_report_filename_for,
)
from backend.app.schemas.scan import (
    ScanCreateRequest,
    ScanEventsResponse,
    ScanFindingsResponse,
    ScanPortsResponse,
    ScanResponse,
)
from backend.app.scanner.validation import TargetValidationError, validate_target
from backend.app.services.scan_manager import (
    ScanCapacityError,
    ScanManager,
    ScanNotFoundError,
    ScanNotReadyError,
)


router = APIRouter(prefix="/api/scans", tags=["scans"])
_SPECIAL_PURPOSE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "192.0.0.0/24",
        "192.88.99.0/24",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2002::/16",
    )
)


def get_scan_manager() -> ScanManager:
    return _manager


_manager = ScanManager.from_environment()


def _validated_public_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or any(
            address.version == network.version and address in network
            for network in _SPECIAL_PURPOSE_NETWORKS
        )
    ):
        raise HTTPException(status_code=403, detail="Target resolves to a non-public or special-purpose address.")
    return address


def resolve_public_scan_address(target: str) -> str:
    """Validate an IP or resolve a hostname once, preventing DNS rebinding."""
    try:
        direct_address = ipaddress.ip_address(target)
    except ValueError:
        direct_address = None
    if direct_address is not None:
        return str(_validated_public_ip(str(direct_address)))
    try:
        answers = socket.getaddrinfo(f"{target}.", None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise HTTPException(status_code=422, detail="The target hostname could not be resolved.") from exc
    addresses: set[str] = set()
    for answer in answers:
        try:
            address = _validated_public_ip(answer[4][0])
        except (ValueError, IndexError, TypeError) as exc:
            raise HTTPException(status_code=422, detail="DNS returned an invalid address.") from exc
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        addresses.add(str(address))
    if not addresses:
        raise HTTPException(status_code=422, detail="The target hostname has no usable address records.")
    # One scan request may target only one resolved address. Sorted order keeps
    # selection stable when a hostname has multiple validated public records.
    return sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item))[0]


def _check_owner(manager: ScanManager, scan_id: str, capability: Capability) -> None:
    try:
        manager.ensure_owner(scan_id, capability.owner_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.") from exc


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    request: Request,
    payload: ScanCreateRequest,
    capability: Capability = Depends(require_capability),
    manager: ScanManager = Depends(get_scan_manager),
    settings: Settings = Depends(Settings.from_environment),
) -> ScanResponse:
    client = request.client.host if request.client else "unknown"
    if not allow_rate_attempt("scan", client, settings.scan_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many scan submissions. Try again later.")
    try:
        target = validate_target(payload.target)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan_address = resolve_public_scan_address(target)
    if settings.scan_target_allowlist and target not in settings.scan_target_allowlist and scan_address not in settings.scan_target_allowlist:
        raise HTTPException(status_code=403, detail="Target is not included in the configured scan allowlist.")
    try:
        return manager.submit(
            target,
            payload.profile,
            scan_target=scan_address,
            owner_id=capability.owner_id,
        )
    except ScanCapacityError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    capability: Capability = Depends(require_capability),
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanResponse:
    _check_owner(manager, scan_id, capability)
    try:
        return manager.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found.") from exc


@router.post("/{scan_id}/stop", response_model=ScanResponse)
def stop_scan(
    scan_id: str,
    capability: Capability = Depends(require_capability),
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanResponse:
    _check_owner(manager, scan_id, capability)
    try:
        return manager.stop(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found.") from exc


@router.get("/{scan_id}/ports", response_model=ScanPortsResponse)
def get_scan_ports(
    scan_id: str,
    capability: Capability = Depends(require_capability),
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanPortsResponse:
    _check_owner(manager, scan_id, capability)
    try:
        return manager.get_ports(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found.") from exc
    except ScanNotReadyError as exc:
        raise HTTPException(status_code=409, detail=f"Scan is not complete; current status is {exc}.") from exc


@router.get("/{scan_id}/events", response_model=ScanEventsResponse)
def get_scan_events(
    scan_id: str,
    after: int = Query(default=0, ge=0),
    capability: Capability = Depends(require_capability),
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanEventsResponse:
    _check_owner(manager, scan_id, capability)
    try:
        return manager.get_events(scan_id, after)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found.") from exc


@router.get("/{scan_id}/findings", response_model=ScanFindingsResponse)
def get_scan_findings(
    scan_id: str,
    capability: Capability = Depends(require_capability),
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanFindingsResponse:
    _check_owner(manager, scan_id, capability)
    try:
        return manager.get_findings(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found.") from exc
    except ScanNotReadyError as exc:
        raise HTTPException(status_code=409, detail=f"Scan is not complete; current status is {exc}.") from exc


@router.get("/{scan_id}/report", response_class=Response)
def get_scan_report(
    scan_id: str,
    format: str = Query(default="html"),
    capability: Capability = Depends(require_capability),
    manager: ScanManager = Depends(get_scan_manager),
) -> Response:
    _check_owner(manager, scan_id, capability)
    try:
        report_data = manager.get_report_data(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found.") from exc
    except ScanNotReadyError as exc:
        raise HTTPException(status_code=409, detail=f"Scan is not complete; current status is {exc}.") from exc
    generators = {
        "html": (generate_html_report, "text/html", "html"),
        "json": (generate_json_report, "application/json", "json"),
        "pdf": (generate_pdf_report, "application/pdf", "pdf"),
    }
    generator_info = generators.get(format.lower())
    if generator_info is None:
        raise HTTPException(status_code=400, detail="Unsupported report format. Use html, json, or pdf.")
    generator, media_type, extension = generator_info
    return Response(
        content=generator(report_data),
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f'attachment; filename="{safe_report_filename_for(report_data.scan.scan_id, extension)}"'
            )
        },
    )
