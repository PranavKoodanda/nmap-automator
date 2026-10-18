"""Scan API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Response, status

from backend.app.config import Settings
from backend.app.reports.html_report import generate_html_report, safe_report_filename
from backend.app.schemas.scan import (
    ScanCreateRequest,
    ScanFindingsResponse,
    ScanPortsResponse,
    ScanResponse,
)
from backend.app.services.scan_manager import (
    ScanCapacityError,
    ScanManager,
    ScanNotFoundError,
    ScanNotReadyError,
)


router = APIRouter(prefix="/api/scans", tags=["scans"])


def get_settings() -> Settings:
    return Settings.from_environment()


def get_scan_manager() -> ScanManager:
    return _manager


_manager = ScanManager()


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    request: ScanCreateRequest,
    settings: Settings = Depends(get_settings),
    manager: ScanManager = Depends(get_scan_manager),
) -> ScanResponse:
    if not settings.is_target_authorized(request.target):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target is outside the configured scan authorization policy.",
        )
    try:
        return manager.submit(request.target, request.profile)
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
    return Response(
        content=generate_html_report(report_data),
        media_type="text/html",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{safe_report_filename(report_data.scan.scan_id)}"'
            )
        },
    )
