import os
import secrets
import socket
import time

os.environ["APP_AUTH_SECRET"] = secrets.token_urlsafe(32)

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pytest

from backend.app import auth
from backend.app.api import scans
from backend.app.api.scans import get_scan_manager
from backend.app.config import Settings
from backend.app.main import create_app
from backend.app.scanner.engine import ScanExecutionResult
from backend.app.scanner.parser import ScanResult
from backend.app.scanner.profiles import ScanProfile
from backend.app.services.scan_manager import ScanManager

REAL_RESOLVER = scans.resolve_public_scan_address


def _scan(target, profile, **kwargs):
    return ScanExecutionResult(
        target=target,
        profile=profile,
        scan=ScanResult(target=target, ports=()),
        stderr="",
        returncode=0,
    )


def _dns_result(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (address, 0))]


def _session_token(client):
    response = client.post("/api/session")
    assert response.status_code == 201
    return response.json()["access_token"]


def _reset_limiter(monkeypatch):
    monkeypatch.setattr(auth, "_rate_attempts", {})
    monkeypatch.setattr(auth, "_next_cleanup_at", 0.0)


@pytest.fixture(autouse=True)
def mock_public_resolution(monkeypatch):
    monkeypatch.setattr(scans, "resolve_public_scan_address", lambda target: "8.8.8.8")


def _client_with_manager(scanner=None):
    manager = ScanManager(scanner=scanner or _scan, max_workers=1, max_pending=4)
    app = create_app()
    app.dependency_overrides[get_scan_manager] = lambda: manager
    return TestClient(app), manager


def test_anonymous_session_is_issued_automatically_and_signed(monkeypatch):
    _reset_limiter(monkeypatch)
    client = TestClient(create_app())
    response = client.post("/api/session")
    assert response.status_code == 201
    token = response.json()["access_token"]
    decoded = auth.decode_capability(token, Settings.from_environment())
    assert decoded is not None
    assert len(decoded.owner_id) >= 20
    assert response.json()["expires_in"] == Settings.from_environment().capability_ttl_seconds


@pytest.mark.parametrize("address", ["8.8.4.4", "2606:4700:4700::1111"])
def test_valid_public_ip_starts_without_dns_verification(monkeypatch, address):
    client, manager = _client_with_manager()
    monkeypatch.setattr(scans, "resolve_public_scan_address", lambda target: str(scans._validated_public_ip(target)))
    try:
        token = _session_token(client)
        response = client.post(
            "/api/scans",
            json={"target": address, "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 202
        assert response.json()["target"] == address
    finally:
        manager.shutdown()


def test_public_hostname_starts_and_nmap_receives_pinned_address(monkeypatch):
    scanned = []

    def scanner(target, profile, **kwargs):
        scanned.append(target)
        return _scan(target, profile)

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _dns_result("8.8.8.8"))
    client, manager = _client_with_manager(scanner)
    # Call the real resolver with mocked DNS rather than relying on the fixture stub.
    monkeypatch.setattr(scans, "resolve_public_scan_address", REAL_RESOLVER)
    try:
        token = _session_token(client)
        response = client.post(
            "/api/scans",
            json={"target": "public.example.test", "profile": "basic_tcp"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 202
        assert response.json()["target"] == "public.example.test"
        for _ in range(100):
            if scanned:
                break
            time.sleep(0.01)
        assert scanned == ["8.8.8.8"]
    finally:
        manager.shutdown()


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1", "10.0.0.4", "169.254.1.2", "::1", "fc00::1", "fe80::1",
        "224.0.0.1", "255.255.255.255", "192.0.2.8", "100.64.0.1", "192.0.0.9",
        "2002:c000:0201::1",
    ],
)
def test_private_and_special_addresses_are_rejected(address):
    with pytest.raises(HTTPException) as error:
        scans._validated_public_ip(address)
    assert error.value.status_code == 403


def test_hostname_mixed_public_and_private_answers_are_rejected(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: _dns_result("8.8.8.8") + _dns_result("10.0.0.1"),
    )
    with pytest.raises(HTTPException) as error:
        REAL_RESOLVER("mixed.example.test")
    assert error.value.status_code == 403


@pytest.mark.parametrize("target", ["http://example.com", "192.0.2.0/24", "bad host", "", "999.1.1.1"])
def test_invalid_target_inputs_are_rejected_before_scan(target):
    client, manager = _client_with_manager()
    try:
        token = _session_token(client)
        response = client.post(
            "/api/scans",
            json={"target": target, "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422
    finally:
        manager.shutdown()


def test_unsupported_profile_is_rejected():
    client, manager = _client_with_manager()
    try:
        token = _session_token(client)
        response = client.post(
            "/api/scans",
            json={"target": "example.com", "profile": "arbitrary_nmap_flags"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422
    finally:
        manager.shutdown()


@pytest.mark.parametrize("profile", ["udp_top_100", "tcp_udp_common"])
def test_hosted_api_returns_clear_error_for_udp_profiles(monkeypatch, profile):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("FRONTEND_CORS_ORIGINS", "https://scanner.example.test")
    client, manager = _client_with_manager()
    try:
        token = _session_token(client)
        response = client.post(
            "/api/scans",
            json={"target": "example.com", "profile": profile},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 422
        assert "UDP scanning is unavailable" in response.json()["detail"]
        assert "TCP-only profile" in response.json()["detail"]
    finally:
        manager.shutdown()


def test_sessions_isolate_scan_history_and_session_creation_is_rate_limited(monkeypatch):
    _reset_limiter(monkeypatch)
    monkeypatch.setenv("ANONYMOUS_SESSION_LIMIT", "2")
    client, manager = _client_with_manager()
    try:
        first = _session_token(client)
        second = _session_token(client)
        assert client.post("/api/session").status_code == 429
        created = client.post(
            "/api/scans",
            json={"target": "example.com", "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {first}"},
        )
        scan_id = created.json()["scan_id"]
        foreign_headers = {"Authorization": f"Bearer {second}"}
        for response in (
            client.get(f"/api/scans/{scan_id}", headers=foreign_headers),
            client.get(f"/api/scans/{scan_id}/events", headers=foreign_headers),
            client.get(f"/api/scans/{scan_id}/ports", headers=foreign_headers),
            client.get(f"/api/scans/{scan_id}/findings", headers=foreign_headers),
            client.get(f"/api/scans/{scan_id}/report", headers=foreign_headers),
            client.post(f"/api/scans/{scan_id}/stop", headers=foreign_headers),
        ):
            assert response.status_code == 404
        assert client.get(f"/api/scans/{scan_id}/events", headers={"Authorization": f"Bearer {first}"}).status_code == 200
    finally:
        manager.shutdown()


def test_scan_submission_rate_limit_applies_to_anonymous_sessions(monkeypatch):
    _reset_limiter(monkeypatch)
    monkeypatch.setenv("SCAN_SUBMISSION_LIMIT", "1")
    client, manager = _client_with_manager()
    try:
        token = _session_token(client)
        headers = {"Authorization": f"Bearer {token}"}
        first = client.post("/api/scans", json={"target": "example.com", "profile": "quick_tcp"}, headers=headers)
        second = client.post("/api/scans", json={"target": "8.8.8.8", "profile": "quick_tcp"}, headers=headers)
        assert first.status_code == 202
        assert second.status_code == 429
    finally:
        manager.shutdown()


def test_anonymous_scan_paths_require_capability():
    client = TestClient(create_app())
    assert client.get("/health").status_code == 200
    for response in (
        client.post("/api/scans", json={"target": "8.8.8.8", "profile": "quick_tcp"}),
        client.get("/api/scans/not-found"),
        client.get("/api/scans/not-found/events"),
        client.get("/api/scans/not-found/ports"),
        client.get("/api/scans/not-found/findings"),
        client.get("/api/scans/not-found/report"),
        client.post("/api/scans/not-found/stop"),
    ):
        assert response.status_code == 401
    assert client.post("/api/verification/challenges", json={"hostname": "x.example.com"}).status_code == 404
    assert client.post("/api/verification/verify", json={"challenge_id": "x"}).status_code == 404
