"""Environment-backed safety and lifecycle configuration."""

from collections import Counter
from dataclasses import dataclass
import math
import os
import re
from urllib.parse import urlsplit


MAX_CONCURRENT_SCANS = 16
MAX_PENDING_SCANS = 64
_PLACEHOLDER_PATTERN = re.compile(
    r"(?i)(placeholder|replace[-_\s]?with|change[-_\s]?me|"
    r"your(?:[-_\s][a-z0-9]+){0,3}[-_\s](?:secret|password)|"
    r"(?:^|[-_\s])(?:example|sample)(?:$|[-_\s])|"
    r"(?:secret|password)[-_\s]?goes[-_\s]?here|"
    r"<[^>]+>|\b(?:insert|set)[-_\s]?me\b)"
)


@dataclass(frozen=True, slots=True)
class Settings:
    cors_origins: tuple[str, ...]
    max_concurrent_scans: int
    max_pending_scans: int
    app_env: str
    app_auth_secret: str
    capability_ttl_seconds: int
    verification_challenge_ttl_seconds: int
    rate_limit_window_seconds: int
    challenge_rate_limit: int
    verification_rate_limit: int
    scan_rate_limit: int
    scan_target_allowlist: tuple[str, ...]

    @classmethod
    def from_environment(cls) -> "Settings":
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        if app_env not in {"development", "production"}:
            raise ValueError("APP_ENV must be either development or production.")
        secret = os.getenv("APP_AUTH_SECRET", "")
        if not _is_strong_secret(secret):
            raise ValueError(
                "APP_AUTH_SECRET must be set to a non-placeholder, high-entropy secret of at least 32 characters."
            )

        configured_origins = tuple(
            origin.strip()
            for origin in os.getenv("FRONTEND_CORS_ORIGINS", "http://localhost:5173").split(",")
            if origin.strip()
        )
        if app_env == "production":
            raw_origins = os.getenv("FRONTEND_CORS_ORIGINS", "")
            configured_origins = tuple(origin.strip() for origin in raw_origins.split(",") if origin.strip())
            if not configured_origins:
                raise ValueError("FRONTEND_CORS_ORIGINS must contain explicit frontend origins in production.")
            try:
                for origin in configured_origins:
                    _validate_production_origin(origin)
            except ValueError as exc:
                raise ValueError(
                    "FRONTEND_CORS_ORIGINS must contain only explicit HTTPS origins without paths, wildcards, or credentials."
                ) from exc

        allowlist = tuple(
            item.strip()
            for item in os.getenv("SCAN_TARGET_ALLOWLIST", "").split(",")
            if item.strip()
        )
        if allowlist:
            from backend.app.scanner.validation import validate_target

            try:
                allowlist = tuple(validate_target(item) for item in allowlist)
            except ValueError as exc:
                raise ValueError("SCAN_TARGET_ALLOWLIST must contain only valid IP addresses and hostnames.") from exc

        return cls(
            cors_origins=configured_origins,
            max_concurrent_scans=_positive_int_setting(
                "MAX_CONCURRENT_SCANS", 2, MAX_CONCURRENT_SCANS
            ),
            max_pending_scans=_positive_int_setting("MAX_PENDING_SCANS", 4, MAX_PENDING_SCANS),
            app_env=app_env,
            app_auth_secret=secret,
            capability_ttl_seconds=_positive_int_setting("APP_CAPABILITY_TTL_SECONDS", 3600, 86400),
            verification_challenge_ttl_seconds=_positive_int_setting(
                "DOMAIN_CHALLENGE_TTL_SECONDS", 600, 3600
            ),
            rate_limit_window_seconds=_positive_int_setting("PUBLIC_RATE_WINDOW_SECONDS", 3600, 86400),
            challenge_rate_limit=_positive_int_setting("DOMAIN_CHALLENGE_LIMIT", 10, 100),
            verification_rate_limit=_positive_int_setting("DOMAIN_VERIFICATION_LIMIT", 20, 100),
            scan_rate_limit=_positive_int_setting("SCAN_SUBMISSION_LIMIT", 20, 100),
            scan_target_allowlist=allowlist,
        )


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_PATTERN.search(value))


def _is_strong_secret(value: str | None) -> bool:
    if value is None or len(value) < 32 or _is_placeholder(value):
        return False
    entropy = -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in Counter(value).values()
    )
    return entropy >= 3.5


def _validate_production_origin(origin: str) -> None:
    if "*" in origin:
        raise ValueError("Wildcards are not allowed in production CORS origins.")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("A production CORS origin must be an explicit HTTPS origin.")
    _ = parsed.port
    from backend.app.scanner.validation import validate_target

    validate_target(parsed.hostname)


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
