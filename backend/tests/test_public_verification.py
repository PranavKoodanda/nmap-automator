import os
import secrets
import socket

os.environ["APP_AUTH_SECRET"] = secrets.token_urlsafe(32)

from fastapi.testclient import TestClient
import pytest

from backend.app import auth
from backend.app.api import scans
from backend.app.config import Settings
from backend.app.main import create_app
from backend.app.scanner.engine import ScanExecutionResult
from backend.app.scanner.parser import ScanResult
from backend.app.scanner.profiles import ScanProfile
from backend.app.services.scan_manager import ScanManager

REAL_RESOLVE_PUBLIC_ADDRESS = scans.resolve_public_scan_address


def client_with_manager(scanner=None):
    manager = ScanManager(scanner=scanner or _empty_scan, max_workers=1, max_pending=4)
    app = create_app()
    from backend.app.api.scans import get_scan_manager

    app.dependency_overrides[get_scan_manager] = lambda: manager
    return TestClient(app), manager


def _empty_scan(target, profile, **kwargs):
    return ScanExecutionResult(
        target=target,
        profile=profile,
        scan=ScanResult(target=target, ports=()),
        stderr="",
        returncode=0,
    )


def _capability(hostname, owner="visitor-owner-01234567890123456789"):
    return auth.issue_capability(hostname, owner, Settings.from_environment())


def _txt_result(address, port=0):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]


def _reset_state(monkeypatch):
    monkeypatch.setattr(auth, "_rate_attempts", {})
    monkeypatch.setattr(auth, "_challenges", {})
    monkeypatch.setattr(auth, "_next_cleanup_at", float("inf"))


@pytest.fixture(autouse=True)
def mock_scan_resolution(monkeypatch):
    monkeypatch.setattr(scans, "resolve_public_scan_address", lambda hostname: "8.8.8.8")


def test_dns_challenge_displays_record_and_issues_hostname_scoped_capability(monkeypatch):
    _reset_state(monkeypatch)
    client = TestClient(create_app())
    challenge_response = client.post(
        "/api/verification/challenges",
        json={"hostname": "WWW.Example.Test."},
    )
    assert challenge_response.status_code == 201
    challenge = challenge_response.json()
    assert challenge["hostname"] == "www.example.test"
    assert challenge["record_name"] == "_nmap-automator-verification.www.example.test"
    assert challenge["txt_value"].startswith("nmap-automator-verification=")
    assert challenge["expires_at"]

    monkeypatch.setattr(auth, "lookup_txt_records", lambda name: ("incorrect-proof",))
    invalid = client.post("/api/verification/verify", json={"challenge_id": challenge["challenge_id"]})
    assert invalid.status_code == 400
    monkeypatch.setattr(auth, "lookup_txt_records", lambda name: (challenge["txt_value"],))
    verified = client.post("/api/verification/verify", json={"challenge_id": challenge["challenge_id"]})
    assert verified.status_code == 200
    capability = auth.decode_capability(verified.json()["access_token"], Settings.from_environment())
    assert capability is not None
    assert capability.hostname == "www.example.test"
    assert client.post("/api/verification/verify", json={"challenge_id": challenge["challenge_id"]}).status_code == 404


def test_challenge_expiration_and_storage_are_bounded(monkeypatch):
    _reset_state(monkeypatch)
    monkeypatch.setattr(auth, "MAX_STORED_CHALLENGES", 1)
    client = TestClient(create_app())
    first = client.post("/api/verification/challenges", json={"hostname": "one.example.test"})
    assert first.status_code == 201
    challenge_id = first.json()["challenge_id"]
    assert client.post("/api/verification/challenges", json={"hostname": "two.example.test"}).status_code == 429
    auth._challenges[challenge_id].expires_at = 0
    expired = client.post("/api/verification/verify", json={"challenge_id": challenge_id})
    assert expired.status_code == 410
    renewed = client.post("/api/verification/challenges", json={"hostname": "two.example.test"})
    assert renewed.status_code == 201
    assert len(auth._challenges) == 1


def test_challenge_and_verification_rate_limits(monkeypatch):
    _reset_state(monkeypatch)
    monkeypatch.setenv("DOMAIN_CHALLENGE_LIMIT", "1")
    monkeypatch.setenv("DOMAIN_VERIFICATION_LIMIT", "1")
    client = TestClient(create_app())
    assert client.post("/api/verification/challenges", json={"hostname": "rate.example.test"}).status_code == 201
    assert client.post("/api/verification/challenges", json={"hostname": "rate2.example.test"}).status_code == 429
    assert client.post("/api/verification/verify", json={"challenge_id": "unknown-challenge-id-123456"}).status_code == 404
    assert client.post("/api/verification/verify", json={"challenge_id": "unknown-challenge-id-123456"}).status_code == 429


@pytest.mark.parametrize("hostname", ["localhost", "192.0.2.10", "192.0.2.0/24", "https://example.test"])
def test_challenge_requires_a_fully_qualified_hostname(monkeypatch, hostname):
    _reset_state(monkeypatch)
    client = TestClient(create_app())
    assert client.post("/api/verification/challenges", json={"hostname": hostname}).status_code == 422


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.4", "169.254.1.2", "::1", "224.0.0.1", "192.0.2.8", "100.64.0.1", "192.0.0.9", "2002:c000:0201::1"])
def test_resolver_rejects_non_global_and_special_purpose_addresses(monkeypatch, address):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _txt_result(address))
    with pytest.raises(Exception):
        REAL_RESOLVE_PUBLIC_ADDRESS("scan.example.test")


def test_resolver_rejects_mixed_public_and_private_answers(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: _txt_result("8.8.8.8") + _txt_result("10.0.0.1"),
    )
    with pytest.raises(Exception):
        REAL_RESOLVE_PUBLIC_ADDRESS("scan.example.test")


def test_dns_rebinding_defense_pins_nmap_to_resolved_ip(monkeypatch):
    scanned_targets = []

    def scanner(target, profile, **kwargs):
        scanned_targets.append(target)
        return _empty_scan(target, profile)

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: _txt_result("8.8.4.4"))
    monkeypatch.setattr(scans, "resolve_public_scan_address", REAL_RESOLVE_PUBLIC_ADDRESS)
    client, manager = client_with_manager(scanner)
    try:
        capability = _capability("pinned.example.test")
        response = client.post(
            "/api/scans",
            json={"target": "pinned.example.test", "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {capability}"},
        )
        assert response.status_code == 202
        scan_id = response.json()["scan_id"]
        assert response.json()["target"] == "pinned.example.test"
        for _ in range(100):
            if manager.get(scan_id).status.value == "completed":
                break
        assert scanned_targets == ["8.8.4.4"]
    finally:
        manager.shutdown()


def test_capability_scope_ownership_and_scan_submission_rate_limit(monkeypatch):
    _reset_state(monkeypatch)
    monkeypatch.setenv("SCAN_SUBMISSION_LIMIT", "1")
    client, manager = client_with_manager()
    try:
        owner_a = _capability("alpha.example.test", "owner-alpha-01234567890123456789")
        owner_b = _capability("alpha.example.test", "owner-beta-01234567890123456789")
        other_host = _capability("beta.example.test", "owner-gamma-01234567890123456789")
        created = client.post(
            "/api/scans",
            json={"target": "alpha.example.test", "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {owner_a}"},
        )
        assert created.status_code == 202
        scan_id = created.json()["scan_id"]
        assert client.get(
            f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {owner_b}"}
        ).status_code == 404
        assert client.get(
            f"/api/scans/{scan_id}/events", headers={"Authorization": f"Bearer {other_host}"}
        ).status_code == 404
        auth._rate_attempts.clear()
        assert client.post(
            "/api/scans",
            json={"target": "alpha.example.test", "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {other_host}"},
        ).status_code == 403
        auth._rate_attempts.clear()
        assert client.post(
            "/api/scans",
            json={"target": "alpha.example.test", "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {owner_a}"},
        ).status_code == 202
        assert client.post(
            "/api/scans",
            json={"target": "alpha.example.test", "profile": "quick_tcp"},
            headers={"Authorization": f"Bearer {owner_a}"},
        ).status_code == 429
    finally:
        manager.shutdown()
