"""Anonymous browser-session capabilities and bounded request throttling."""

from collections import deque
from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import secrets
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.app.config import Settings


router = APIRouter(prefix="/api", tags=["anonymous session"])
bearer = HTTPBearer(auto_error=False)
MAX_TRACKED_RATE_BUCKETS = 20_000
_CLEANUP_INTERVAL_SECONDS = 60
_rate_attempts: dict[tuple[str, str], deque[float]] = {}
_state_lock = threading.RLock()
_next_cleanup_at = 0.0


@dataclass(frozen=True, slots=True)
class Capability:
    owner_id: str
    expires_at: int


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_capability(owner_id: str, settings: Settings, now: int | None = None) -> str:
    issued = int(time.time() if now is None else now)
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    claims = {
        "iat": issued,
        "exp": issued + settings.capability_ttl_seconds,
        "kind": "anonymous-scan-session",
        "jti": owner_id,
    }
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signed = f"{header}.{payload}".encode("ascii")
    signature = _b64(hmac.new(settings.app_auth_secret.encode(), signed, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def decode_capability(token: str, settings: Settings, now: int | None = None) -> Capability | None:
    try:
        header, payload, signature = token.split(".")
        if header != _b64(b'{"alg":"HS256","typ":"JWT"}'):
            return None
        signed = f"{header}.{payload}".encode("ascii")
        expected = _b64(hmac.new(settings.app_auth_secret.encode(), signed, hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        claims = json.loads(_unb64(payload))
        current = int(time.time() if now is None else now)
        owner_id = claims.get("jti")
        expires_at = claims.get("exp")
        issued_at = claims.get("iat")
        if (
            claims.get("kind") != "anonymous-scan-session"
            or not isinstance(owner_id, str)
            or len(owner_id) < 20
            or not isinstance(expires_at, int)
            or expires_at <= current
            or not isinstance(issued_at, int)
            or issued_at > current + 30
        ):
            return None
        return Capability(owner_id=owner_id, expires_at=expires_at)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def require_capability(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    settings: Settings = Depends(Settings.from_environment),
) -> Capability:
    capability = (
        decode_capability(credentials.credentials, settings)
        if credentials is not None and credentials.scheme.lower() == "bearer"
        else None
    )
    if capability is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid browser session capability is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return capability


def allow_rate_attempt(
    bucket: str,
    client: str,
    limit: int,
    window: int,
    *,
    now: float | None = None,
) -> bool:
    """Process-local sliding-window limiter with bounded client state."""
    global _next_cleanup_at
    key = (bucket, client)
    with _state_lock:
        now = time.monotonic() if now is None else now
        cutoff = now - window
        if now >= _next_cleanup_at:
            for old_key, history in list(_rate_attempts.items()):
                while history and history[0] <= cutoff:
                    history.popleft()
                if not history:
                    del _rate_attempts[old_key]
            _next_cleanup_at = now + _CLEANUP_INTERVAL_SECONDS

        history = _rate_attempts.get(key)
        if history is not None:
            while history and history[0] <= cutoff:
                history.popleft()
            if not history:
                del _rate_attempts[key]
                history = None
        if history is not None and len(history) >= limit:
            return False
        if history is None:
            if len(_rate_attempts) >= MAX_TRACKED_RATE_BUCKETS:
                for old_key, old_history in list(_rate_attempts.items()):
                    while old_history and old_history[0] <= cutoff:
                        old_history.popleft()
                    if not old_history:
                        del _rate_attempts[old_key]
                if len(_rate_attempts) >= MAX_TRACKED_RATE_BUCKETS:
                    return False
            history = deque()
            _rate_attempts[key] = history
        history.append(now)
        return True


def _client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/session", status_code=status.HTTP_201_CREATED)
def create_anonymous_session(
    request: Request,
    settings: Settings = Depends(Settings.from_environment),
) -> dict[str, object]:
    client = _client_address(request)
    if not allow_rate_attempt("session", client, settings.session_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=429, detail="Too many browser sessions. Try again later.")
    owner_id = secrets.token_urlsafe(24)
    return {
        "access_token": issue_capability(owner_id, settings),
        "token_type": "bearer",
        "expires_in": settings.capability_ttl_seconds,
    }
