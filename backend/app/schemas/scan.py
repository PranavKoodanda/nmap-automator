"""Schemas for the scan API."""

from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.scanner.profiles import ScanProfile
from backend.app.scanner.validation import TargetValidationError, validate_target


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanCreateRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    profile: ScanProfile

    @field_validator("target")
    @classmethod
    def validate_target_syntax(cls, value: str) -> str:
        try:
            return validate_target(value)
        except TargetValidationError as exc:
            raise ValueError(str(exc)) from exc


class PortResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    port: int
    protocol: str
    state: str | None
    service: str | None
    product: str | None
    version: str | None


class ScanSummary(BaseModel):
    reported_ports: int
    open_ports: int
    closed_ports: int
    filtered_ports: int
    unavailable_state_ports: int


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    profile: ScanProfile
    status: ScanStatus
    created_at: datetime
    completed_at: datetime | None = None
    summary: ScanSummary | None = None
    error: str | None = None


class ScanPortsResponse(BaseModel):
    scan_id: str
    target: str
    profile: ScanProfile
    status: ScanStatus
    ports: list[PortResponse]
