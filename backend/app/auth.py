"""DNS ownership challenges and host-scoped signed scan capabilities."""

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
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
from backend.app.scanner.validation import TargetValidationError, validate_fqdn


router = APIRouter(prefix="/api/verification", tags=["domain verification"])
bearer = HTTPBearer(auto_error=False)
MAX_TRACKED_RATE_BUCKETS = 20_000
MAX_STORED_CHALLENGES = 5_000
MAX_CHALLENGE_ATTEMPTS = 5
_CLEANUP_INTERVAL_SECONDS = 60
_rate_attempts: dict[tuple[str, str], deque[float]] = {}
_challenges: dict[str, "Challenge"] = {}
_state_lock = threading.RLock()
_next_cleanup_at = 0.0


@dataclass(frozen=True, slots=True)
class Capability:
    hostname: str
    owner_id: str
    expires_at: int


@dataclass(slots=True)
class Challenge:
    challenge_id: str
    hostname: str
    record_name: str
    expected_value_hash: bytes
    expires_at: float
    attempts: int = 0
    verifying: bool = False


class ChallengeRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)


class VerificationRequest(BaseModel):
    challenge_id: str = Field(min_length=20, max_length=100)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_capability(hostname: str, owner_id: str, settings: Settings, now: int | None = None) -> str:
    issued = int(time.time() if now is None else now)
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    claims = {
        "iat": issued,
        "exp": issued + settings.capability_ttl_seconds,
        "kind": "verified-host-scan",
        "host": hostname,
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
        hostname = validate_fqdn(claims.get("host"))
        if (
            claims.get("kind") != "verified-host-scan"
            or hostname != claims.get("host")
            or not isinstance(claims.get("jti"), str)
            or len(claims["jti"]) < 20
            or not isinstance(claims.get("exp"), int)
            or claims["exp"] <= current
            or not isinstance(claims.get("iat"), int)
            or claims["iat"] > current + 30
        ):
            return None
        return Capability(hostname=hostname, owner_id=claims["jti"], expires_at=claims["exp"])
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
            detail="A valid verified-domain capability is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return capability


def _client_address(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def allow_rate_attempt(
    bucket: str,
    client: str,
    limit: int,
    window: int,
    *,
    now: float | None = None,
) -> bool:
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
            for challenge_id, challenge in list(_challenges.items()):
                if challenge.expires_at <= now:
                    del _challenges[challenge_id]
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


def _allow_challenge_storage(challenge: Challenge) -> bool:
    now = time.monotonic()
    with _state_lock:
        for challenge_id, old in list(_challenges.items()):
            if old.expires_at <= now:
                del _challenges[challenge_id]
        if len(_challenges) >= MAX_STORED_CHALLENGES:
            return False
        _challenges[challenge.challenge_id] = challenge
        return True


def lookup_txt_records(record_name: str) -> tuple[str, ...]:
    """Return TXT record values; DNS failures are treated as absent proof."""
    try:
        import dns.exception
        import dns.resolver

        absolute_name = record_name.rstrip(".") + "."
        answer = dns.resolver.resolve(absolute_name, "TXT", lifetime=4.0, search=False)
        values = []
        for record in answer:
            chunks = getattr(record, "strings", ())
            if chunks:
                values.append(b"".join(chunks).decode("utf-8", errors="replace"))
            else:
                values.append(str(record).strip('"'))
        return tuple(values)
    except Exception as exc:
        # dnspython raises several DNS-specific exceptions; DNS failure is not
        # ownership proof. Keep the public response generic.
        try:
            import dns.exception
        except ImportError:
            raise RuntimeError("DNS verification support is not installed.") from exc
        if isinstance(exc, dns.exception.DNSException) or isinstance(exc, (TimeoutError, OSError)):
            return ()
        raise


@router.post("/challenges", status_code=status.HTTP_201_CREATED)
def create_challenge(
    payload: ChallengeRequest,
    request: Request,
    settings: Settings = Depends(Settings.from_environment),
) -> dict[str, object]:
    client = _client_address(request)
    if not allow_rate_attempt("challenge", client, settings.challenge_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=429, detail="Too many verification challenges. Try again later.")
    try:
        hostname = validate_fqdn(payload.hostname)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if settings.scan_target_allowlist and hostname not in settings.scan_target_allowlist:
        raise HTTPException(status_code=403, detail="This hostname is not included in the configured target allowlist.")

    challenge_id = secrets.token_urlsafe(24)
    proof = f"nmap-automator-verification={secrets.token_urlsafe(32)}"
    record_name = f"_nmap-automator-verification.{hostname}"
    challenge = Challenge(
        challenge_id=challenge_id,
        hostname=hostname,
        record_name=record_name,
        expected_value_hash=hashlib.sha256(proof.encode()).digest(),
        expires_at=time.monotonic() + settings.verification_challenge_ttl_seconds,
    )
    if not _allow_challenge_storage(challenge):
        raise HTTPException(status_code=429, detail="Verification capacity is temporarily full. Try again later.")
    expires_at = datetime.fromtimestamp(
        time.time() + settings.verification_challenge_ttl_seconds, timezone.utc
    ).isoformat()
    return {
        "challenge_id": challenge_id,
        "hostname": hostname,
        "record_name": record_name,
        "txt_value": proof,
        "expires_at": expires_at,
    }


@router.post("/verify")
def verify_challenge(
    payload: VerificationRequest,
    request: Request,
    settings: Settings = Depends(Settings.from_environment),
) -> dict[str, object]:
    client = _client_address(request)
    if not allow_rate_attempt("verify", client, settings.verification_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=429, detail="Too many verification attempts. Try again later.")
    with _state_lock:
        challenge = _challenges.get(payload.challenge_id)
        if challenge is None:
            raise HTTPException(status_code=404, detail="Verification challenge was not found.")
        if challenge.expires_at <= time.monotonic():
            del _challenges[payload.challenge_id]
            raise HTTPException(status_code=410, detail="Verification challenge has expired. Create a new challenge.")
        if challenge.verifying:
            raise HTTPException(status_code=409, detail="Verification for this challenge is already in progress.")
        if challenge.attempts >= MAX_CHALLENGE_ATTEMPTS:
            del _challenges[payload.challenge_id]
            raise HTTPException(status_code=429, detail="Challenge attempt limit reached. Create a new challenge.")
        challenge.attempts += 1
        challenge.verifying = True

    try:
        values = lookup_txt_records(challenge.record_name)
    except RuntimeError as exc:
        with _state_lock:
            challenge.verifying = False
        raise HTTPException(status_code=503, detail="DNS verification is unavailable. Try again later.") from exc
    except Exception as exc:
        with _state_lock:
            challenge.verifying = False
        raise HTTPException(status_code=503, detail="DNS verification is temporarily unavailable.") from exc

    verified = any(
        hmac.compare_digest(hashlib.sha256(value.encode()).digest(), challenge.expected_value_hash)
        for value in values
    )
    with _state_lock:
        current = _challenges.get(payload.challenge_id)
        if current is not challenge:
            raise HTTPException(status_code=410, detail="Verification challenge is no longer active.")
        if not verified:
            challenge.verifying = False
            raise HTTPException(status_code=400, detail="The required DNS TXT record was not found.")
        del _challenges[payload.challenge_id]

    owner_id = secrets.token_urlsafe(24)
    token = issue_capability(challenge.hostname, owner_id, settings)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": settings.capability_ttl_seconds,
        "hostname": challenge.hostname,
    }
