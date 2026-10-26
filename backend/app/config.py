"""Environment-backed development safety configuration."""

from dataclasses import dataclass
from collections import Counter
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
    app_access_password: str | None
    app_auth_secret: str | None
    auth_token_ttl_seconds: int
    login_attempt_limit: int
    login_window_seconds: int
    scan_target_allowlist: tuple[str, ...]

    @classmethod
    def from_environment(cls) -> "Settings":
        origins = tuple(
            origin.strip()
            for origin in os.getenv("FRONTEND_CORS_ORIGINS", "http://localhost:5173").split(",")
            if origin.strip()
        )
        app_env = os.getenv("APP_ENV", "development").strip().lower()
        password = os.getenv("APP_ACCESS_PASSWORD")
        secret = os.getenv("APP_AUTH_SECRET")
        allowlist = tuple(x.strip() for x in os.getenv("SCAN_TARGET_ALLOWLIST", "").split(",") if x.strip())
        if app_env == "production":
            if not password or len(password) < 12 or _is_placeholder(password):
                raise ValueError(
                    "APP_ACCESS_PASSWORD must be a non-placeholder value of at least 12 characters in production."
                )
            if not _is_strong_secret(secret):
                raise ValueError(
                    "APP_AUTH_SECRET must be a non-placeholder, high-entropy secret of at least 32 characters in production."
                )
            configured_origins = tuple(
                origin.strip()
                for origin in os.getenv("FRONTEND_CORS_ORIGINS", "").split(",")
                if origin.strip()
            )
            if not configured_origins:
                raise ValueError("FRONTEND_CORS_ORIGINS must contain the deployed frontend origin in production.")
            try:
                for origin in configured_origins:
                    _validate_production_origin(origin)
            except ValueError as exc:
                raise ValueError(
                    "FRONTEND_CORS_ORIGINS must contain only explicit HTTPS origins without paths, wildcards, or credentials."
                ) from exc
            if not allowlist:
                raise ValueError("SCAN_TARGET_ALLOWLIST is required in production.")
            from backend.app.scanner.validation import validate_target
            try:
                for target in allowlist:
                    validate_target(target)
            except ValueError as exc:
                raise ValueError("SCAN_TARGET_ALLOWLIST must contain only valid IP addresses and hostnames.") from exc
            origins = configured_origins
        return cls(
            cors_origins=origins,
            max_concurrent_scans=_positive_int_setting(
                "MAX_CONCURRENT_SCANS", 2, MAX_CONCURRENT_SCANS
            ),
            max_pending_scans=_positive_int_setting(
                "MAX_PENDING_SCANS", 4, MAX_PENDING_SCANS
            ),
            app_env=app_env,
            app_access_password=password,
            app_auth_secret=secret,
            auth_token_ttl_seconds=_positive_int_setting("APP_AUTH_TOKEN_TTL_SECONDS", 3600, 86400),
            login_attempt_limit=_positive_int_setting("APP_LOGIN_ATTEMPT_LIMIT", 5, 100),
            login_window_seconds=_positive_int_setting("APP_LOGIN_WINDOW_SECONDS", 300, 86400),
            scan_target_allowlist=allowlist,
        )


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_PATTERN.search(value))


def _is_strong_secret(value: str | None) -> bool:
    if value is None or len(value) < 32 or _is_placeholder(value):
        return False
    frequencies = Counter(value).values()
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in frequencies)
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
    # Accessing .port validates its syntax and range.
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
