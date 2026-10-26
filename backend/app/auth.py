"""Password login, signed bearer tokens, and bounded login throttling."""

from collections import deque
import hashlib
import hmac
import json
import secrets
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from backend.app.config import Settings


router = APIRouter(prefix="/api/auth", tags=["authentication"])
bearer = HTTPBearer(auto_error=False)
MAX_TRACKED_LOGIN_CLIENTS = 10_000
_LOGIN_CLEANUP_INTERVAL_SECONDS = 60
_attempts: dict[str, deque[float]] = {}
_attempt_lock = threading.Lock()
_next_cleanup_at = 0.0


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_token(settings: Settings, now: int | None = None) -> str:
    if not settings.app_auth_secret:
        raise RuntimeError("APP_AUTH_SECRET is not configured.")
    issued = int(time.time() if now is None else now)
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    claims = {"iat": issued, "exp": issued + settings.auth_token_ttl_seconds, "sub": "app-user"}
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signed = f"{header}.{payload}".encode("ascii")
    signature = _b64(hmac.new(settings.app_auth_secret.encode(), signed, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def validate_token(token: str, settings: Settings, now: int | None = None) -> bool:
    try:
        header, payload, signature = token.split(".")
        if header != _b64(b'{"alg":"HS256","typ":"JWT"}') or not settings.app_auth_secret:
            return False
        signed = f"{header}.{payload}".encode("ascii")
        expected = _b64(hmac.new(settings.app_auth_secret.encode(), signed, hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return False
        import base64
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        current = int(time.time() if now is None else now)
        return (
            claims.get("sub") == "app-user"
            and isinstance(claims.get("exp"), int)
            and claims["exp"] > current
            and isinstance(claims.get("iat"), int)
            and claims["iat"] <= current + 30
        )
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def require_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    settings: Settings = Depends(Settings.from_environment),
) -> None:
    if credentials is None or credentials.scheme.lower() != "bearer" or not validate_token(credentials.credentials, settings):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.", headers={"WWW-Authenticate": "Bearer"})


def _record_login_attempt(
    client: str,
    now: float,
    attempt_limit: int,
    window_seconds: int,
) -> bool:
    """Record one login attempt while keeping process-local state bounded."""
    global _next_cleanup_at
    cutoff = now - window_seconds
    with _attempt_lock:
        if now >= _next_cleanup_at:
            for address, history in list(_attempts.items()):
                while history and history[0] <= cutoff:
                    history.popleft()
                if not history:
                    del _attempts[address]
            _next_cleanup_at = now + _LOGIN_CLEANUP_INTERVAL_SECONDS

        history = _attempts.get(client)
        if history is not None:
            while history and history[0] <= cutoff:
                history.popleft()
            if not history:
                del _attempts[client]
                history = None
        if history is not None and len(history) >= attempt_limit:
            return False

        if history is None:
            if len(_attempts) >= MAX_TRACKED_LOGIN_CLIENTS:
                # Expired clients can be evicted immediately at capacity. Keep
                # active histories intact; otherwise address churn could clear
                # a client's throttling state. Saturation uses the same 429.
                for address, stale_history in list(_attempts.items()):
                    while stale_history and stale_history[0] <= cutoff:
                        stale_history.popleft()
                    if not stale_history:
                        del _attempts[address]
                if len(_attempts) >= MAX_TRACKED_LOGIN_CLIENTS:
                    return False
            history = deque()
            _attempts[client] = history
        history.append(now)
        return True


@router.post("/login")
def login(
    payload: LoginRequest,
    request: Request,
    settings: Settings = Depends(Settings.from_environment),
) -> dict[str, object]:
    if not settings.app_access_password or not settings.app_auth_secret:
        raise HTTPException(status_code=503, detail="Authentication is not configured.")
    client = request.client.host if request.client else "unknown"
    if not _record_login_attempt(
        client,
        time.monotonic(),
        settings.login_attempt_limit,
        settings.login_window_seconds,
    ):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    if not secrets.compare_digest(payload.password, settings.app_access_password):
        raise HTTPException(status_code=401, detail="Invalid password.")
    token = issue_token(settings)
    return {"access_token": token, "token_type": "bearer", "expires_in": settings.auth_token_ttl_seconds}
