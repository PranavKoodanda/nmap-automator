"""Environment-backed development safety configuration."""

from dataclasses import dataclass
import os


MAX_CONCURRENT_SCANS = 16
MAX_PENDING_SCANS = 64


@dataclass(frozen=True, slots=True)
class Settings:
    cors_origins: tuple[str, ...]
    max_concurrent_scans: int
    max_pending_scans: int

    @classmethod
    def from_environment(cls) -> "Settings":
        origins = tuple(
            origin.strip()
            for origin in os.getenv("FRONTEND_CORS_ORIGINS", "http://localhost:5173").split(",")
            if origin.strip()
        )
        return cls(
            cors_origins=origins,
            max_concurrent_scans=_positive_int_setting(
                "MAX_CONCURRENT_SCANS", 2, MAX_CONCURRENT_SCANS
            ),
            max_pending_scans=_positive_int_setting(
                "MAX_PENDING_SCANS", 4, MAX_PENDING_SCANS
            ),
        )


def _positive_int_setting(name: str, default: int, maximum: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer.") from exc
    if value < 1 or value > maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}.")
    return value
