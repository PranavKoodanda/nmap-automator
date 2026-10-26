"""Scan API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from backend.app.reports.html_report import (
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
    safe_report_filename_for,
)
from backend.app.schemas.scan import (
    ScanCreateRequest,
    ScanFindingsResponse,
    ScanPortsResponse,
    ScanResponse,
    ScanEventsResponse,
)
from backend.app.services.scan_manager import (
    ScanCapacityError,
    ScanManager,
    ScanNotFoundError,
    ScanNotReadyError,
)
from backend.app.auth import require_auth
from backend.app.config import Settings
from backend.app.scanner.validation import validate_target


router = APIRouter(prefix="/api/scans", tags=["scans"], dependencies=[Depends(require_auth)])


def get_scan_manager() -> ScanManager:
    return _manager


_manager = ScanManager.from_environment()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    request: ScanCreateRequest,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanResponse:
    settings = Settings.from_environment()
    normalized_target = validate_target(request.target)
    allowed = {validate_target(item) for item in settings.scan_target_allowlist}
    if settings.app_env == "production" and normalized_target not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Target is not in SCAN_TARGET_ALLOWLIST.")
    if settings.scan_target_allowlist and normalized_target not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Target is not in SCAN_TARGET_ALLOWLIST.")
    try:
        return manager.submit(normalized_target, request.profile)
    except ScanCapacityError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanResponse:
    try:
        return manager.get(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.") from exc


@router.post("/{scan_id}/stop", response_model=ScanResponse)
def stop_scan(
    scan_id: str,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanResponse:
    try:
        return manager.stop(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.") from exc


@router.get("/{scan_id}/ports", response_model=ScanPortsResponse)
def get_scan_ports(
    scan_id: str,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanPortsResponse:
    try:
        return manager.get_ports(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.") from exc
    except ScanNotReadyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is not complete; current status is {exc}.",
        ) from exc


@router.get("/{scan_id}/events", response_model=ScanEventsResponse)
def get_scan_events(
    scan_id: str,
    after: int = Query(default=0, ge=0),
    manager: ScanManager = Depends(get_scan_manager),
):
    try:
        return manager.get_events(scan_id, after)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Scan not found.") from exc


@router.get("/{scan_id}/findings", response_model=ScanFindingsResponse)
def get_scan_findings(
    scan_id: str,
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanFindingsResponse:
    try:
        return manager.get_findings(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.") from exc
    except ScanNotReadyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is not complete; current status is {exc}.",
        ) from exc


@router.get("/{scan_id}/report", response_class=Response)
def get_scan_report(
    scan_id: str,
    format: str = Query(default="html"),
    manager: ScanManager = Depends(get_scan_manager),
) -> Response:
    try:
        report_data = manager.get_report_data(scan_id)
    except ScanNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.") from exc
    except ScanNotReadyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is not complete; current status is {exc}.",
        ) from exc
    generators = {
        "html": (generate_html_report, "text/html", "html"),
        "json": (generate_json_report, "application/json", "json"),
        "pdf": (generate_pdf_report, "application/pdf", "pdf"),
    }
    generator_info = generators.get(format.lower())
    if generator_info is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported report format. Use html, json, or pdf.",
        )
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
