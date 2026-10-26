from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from unittest.mock import Mock
import pytest

os.environ["APP_AUTH_SECRET"] = secrets.token_urlsafe(32)
os.environ["ANONYMOUS_SESSION_LIMIT"] = "100"
os.environ["SCAN_SUBMISSION_LIMIT"] = "100"

from fastapi.testclient import TestClient

from backend.app import auth as auth_module
from backend.app.auth import decode_capability, issue_capability
from backend.app.api.scans import get_scan_manager
from backend.app.config import Settings
from backend.app.main import create_app
from backend.app.schemas.scan import ScanStatus
from backend.app.scanner.engine import (
    NmapTimeoutError,
    ProgressUpdate,
    ScanEvent,
    ScanExecutionResult,
    _terminate_process,
)
from backend.app.scanner.parser import PortResult, ScanResult, ServiceMetadata
from backend.app.scanner.profiles import ScanProfile
from backend.app.services.scan_manager import ScanManager
from backend.app.api import scans as scans_api
REAL_RESOLVE_PUBLIC_SCAN_ADDRESS = scans_api.resolve_public_scan_address


def execution_result(target: str = "127.0.0.1") -> ScanExecutionResult:
    return ScanExecutionResult(
        target=target,
        profile=ScanProfile.BASIC_TCP,
        scan=ScanResult(
            target=target,
            ports=(
                PortResult(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service=ServiceMetadata(name="ssh"),
                ),
            ),
        ),
        stderr="",
        returncode=0,
    )


class AuthenticatedTestClient(TestClient):
    def __init__(self, app):
        super().__init__(app)
        self.token = issue_capability(secrets.token_urlsafe(24), Settings.from_environment())

    def request(self, method, url, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        path = url.split("?", 1)[0]
        token = headers.get("Authorization", "").removeprefix("Bearer ") or self.token
        payload = kwargs.get("json")
        if method.upper() == "POST" and path == "/api/scans" and isinstance(payload, dict):
            payload = dict(payload)
            original = payload.get("target")
            test_hosts = {
                "127.0.0.1": "scan.example.test",
                "192.0.2.10": "scan-a.example.test",
                "192.0.2.11": "scan-b.example.test",
            }
            if original in test_hosts:
                payload["target"] = test_hosts[original]
                kwargs["json"] = payload
            hostname = payload.get("target")
            if isinstance(hostname, str) and hostname in {"192.0.2.10", "192.0.2.11"}:
                payload["target"] = "scan-a.example.test" if hostname.endswith("10") else "scan-b.example.test"
                kwargs["json"] = payload
        if token:
            headers["Authorization"] = f"Bearer {token}"
        response = super().request(method, url, headers=headers, **kwargs)
        return response


@pytest.fixture(autouse=True)
def mock_public_dns(monkeypatch):
    def resolve(hostname):
        try:
            import ipaddress
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            return REAL_RESOLVE_PUBLIC_SCAN_ADDRESS(hostname)
        return {
            "scan-a.example.test": "8.8.8.10",
            "scan-b.example.test": "8.8.8.11",
        }.get(hostname, "8.8.8.8")

    monkeypatch.setattr(scans_api, "resolve_public_scan_address", resolve)


def client_for(scanner=None, *, max_pending: int = 4) -> tuple[TestClient, ScanManager]:
    manager = ScanManager(
        scanner=scanner or Mock(return_value=execution_result()),
        max_workers=1,
        max_pending=max_pending,
    )
    app = create_app()
    app.dependency_overrides[get_scan_manager] = lambda: manager
    return AuthenticatedTestClient(app), manager


def test_capability_auth_expiry_rate_limit_and_unauthorized_scan_routes() -> None:
    app = create_app()
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    blocked = client.get("/api/scans/missing")
    assert blocked.status_code == 401
    protected_requests = [
        client.post("/api/scans", json={"target": "127.0.0.1", "profile": "basic_tcp"}),
        client.get("/api/scans/missing/events"),
        client.get("/api/scans/missing/ports"),
        client.get("/api/scans/missing/findings"),
        client.get("/api/scans/missing/report"),
        client.post("/api/scans/missing/stop"),
    ]
    assert all(response.status_code == 401 for response in protected_requests)
    settings = Settings.from_environment()
    token = issue_capability(secrets.token_urlsafe(24), settings, now=100)
    assert decode_capability(token, settings, now=101) is not None
    assert decode_capability(token, settings, now=100 + settings.capability_ttl_seconds) is None
    assert decode_capability(token + "x", settings) is None


def test_production_requires_allowlisted_targets(monkeypatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("APP_AUTH_SECRET", secrets.token_urlsafe(48))
    monkeypatch.setenv("FRONTEND_CORS_ORIGINS", "https://example.test")
    monkeypatch.setenv("SCAN_TARGET_ALLOWLIST", "authorized.example")
    client, manager = client_for()
    try:
        denied = client.post("/api/scans", json={"target": "other.example", "profile": "basic_tcp"})
        assert denied.status_code == 403
        accepted = client.post("/api/scans", json={"target": "authorized.example", "profile": "basic_tcp"})
        assert accepted.status_code == 202
    finally:
        manager.shutdown()


def test_session_rate_limit_expires_and_cleans_old_client_entries(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "_rate_attempts", {})
    monkeypatch.setattr(auth_module, "_next_cleanup_at", 0.0)
    assert auth_module.allow_rate_attempt("session", "192.0.2.1", 2, 300, now=10)
    assert auth_module.allow_rate_attempt("session", "192.0.2.1", 2, 300, now=11)
    assert not auth_module.allow_rate_attempt("session", "192.0.2.1", 2, 300, now=12)
    assert auth_module.allow_rate_attempt("session", "192.0.2.2", 2, 300, now=400)
    assert ("session", "192.0.2.1") not in auth_module._rate_attempts


def test_session_rate_limiter_evicts_safely_at_hard_client_limit(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "_rate_attempts", {})
    monkeypatch.setattr(auth_module, "_next_cleanup_at", float("inf"))
    monkeypatch.setattr(auth_module, "MAX_TRACKED_RATE_BUCKETS", 32)
    for index in range(32):
        assert auth_module.allow_rate_attempt("session", f"198.51.100.{index}", 5, 300, now=index + 1)
    assert not auth_module.allow_rate_attempt("session", "198.51.100.32", 5, 300, now=40)
    assert len(auth_module._rate_attempts) == 32
    assert ("session", "198.51.100.0") in auth_module._rate_attempts
    assert ("session", "198.51.100.32") not in auth_module._rate_attempts
    assert auth_module.allow_rate_attempt("session", "198.51.100.32", 5, 300, now=400)
    assert len(auth_module._rate_attempts) == 1


def test_concurrent_session_attempts_keep_limiter_state_bounded(monkeypatch) -> None:
    monkeypatch.setattr(auth_module, "_rate_attempts", {})
    monkeypatch.setattr(auth_module, "_next_cleanup_at", float("inf"))
    monkeypatch.setattr(auth_module, "MAX_TRACKED_RATE_BUCKETS", 64)
    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(
            lambda index: auth_module.allow_rate_attempt(
                "session", f"203.0.113.{index}", 5, 300
            ),
            range(256),
        ))
    assert sum(outcomes) == 64
    assert len(auth_module._rate_attempts) == 64
    assert all(len(history) == 1 for history in auth_module._rate_attempts.values())


def wait_for_status(client: TestClient, scan_id: str, status: str) -> dict:
    for _ in range(100):
        response = client.get(f"/api/scans/{scan_id}")
        if response.json()["status"] == status:
            return response.json()
        time.sleep(0.01)
    raise AssertionError(f"scan did not reach {status}")


def test_create_complete_and_get_ports() -> None:
    client, manager = client_for()
    try:
        response = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        )
        assert response.status_code == 202
        scan = wait_for_status(client, response.json()["scan_id"], "completed")
        assert scan["summary"]["open_ports"] == 1
        ports = client.get(f"/api/scans/{scan['scan_id']}/ports")
        assert ports.status_code == 200
        assert ports.json()["ports"][0]["service"] == "ssh"
        findings = client.get(f"/api/scans/{scan['scan_id']}/findings")
        assert findings.status_code == 200
        assert findings.json()["findings"] == []
        report = client.get(f"/api/scans/{scan['scan_id']}/report")
        assert report.status_code == 200
        assert report.headers["content-type"] == "text/html; charset=utf-8"
        assert report.headers["content-disposition"] == (
            f'attachment; filename="security-assessment-{scan["scan_id"]}.html"'
        )
        assert "Security Assessment Report" in report.text
    finally:
        manager.shutdown()


def test_events_are_available_before_scan_process_finishes() -> None:
    started = threading.Event()
    release = threading.Event()

    def scanner(target, profile, *, event_callback):
        event_callback(ScanEvent("stage", f"{target} started"))
        started.set()
        release.wait(timeout=2)
        event_callback(ScanEvent("completed", f"{target} process finished"))
        return execution_result(target)

    client, manager = client_for(scanner)
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        assert started.wait(timeout=1)
        events = client.get(
            f"/api/scans/{created['scan_id']}/events?after=0"
        ).json()
        assert events["events"][-1]["message"] == "8.8.8.8 started"
        assert client.get(f"/api/scans/{created['scan_id']}").json()["status"] == "running"
    finally:
        release.set()
        manager.shutdown()


def test_matching_progress_and_output_callbacks_create_one_event() -> None:
    release = threading.Event()
    message = "Stats: About 50% done; 1 undergoing Connect Scan"

    def scanner(target, profile, *, progress_callback, event_callback):
        event_callback(ScanEvent("progress", message))
        progress_callback(
            ProgressUpdate(
                stage="connect scan",
                percent=50,
                elapsed_seconds=1,
                estimated_remaining_seconds=None,
                message=message,
            )
        )
        release.wait(timeout=2)
        return execution_result(target)

    client, manager = client_for(scanner)
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        events = client.get(
            f"/api/scans/{created['scan_id']}/events?after=0"
        ).json()["events"]
        matches = [event for event in events if event["message"] == message]
        assert len(matches) == 1
        assert matches[0]["event_type"] == "progress"
    finally:
        release.set()
        manager.shutdown()


def test_completed_scan_history_keeps_terminal_events_available() -> None:
    def scanner(target, profile, *, event_callback):
        event_callback(ScanEvent("stage", "Controlled scan started."))
        event_callback(ScanEvent("info", "Found controlled output."))
        return execution_result(target)

    client, manager = client_for(scanner)
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        completed = wait_for_status(client, created["scan_id"], "completed")
        reopened_scan = client.get(f"/api/scans/{completed['scan_id']}").json()
        reopened_events = client.get(
            f"/api/scans/{completed['scan_id']}/events?after=0"
        ).json()["events"]

        assert reopened_scan["status"] == "completed"
        assert [event["message"] for event in reopened_events][-3:] == [
            "Controlled scan started.",
            "Found controlled output.",
            "Scan completed.",
        ]
        assert reopened_events[-1]["event_type"] == "completed"
    finally:
        manager.shutdown()


def test_real_delayed_child_events_reach_api_before_exit() -> None:
    started = threading.Event()
    release = threading.Event()

    def scanner(target, profile, *, event_callback):
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys,time; "
                "print('child-one', flush=True); time.sleep(0.4); "
                "print('child-two', flush=True); time.sleep(0.4)",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for line in child.stdout:
                event_callback(ScanEvent("info", line.strip()))
                started.set()
            child.wait(timeout=2)
            release.set()
            return execution_result(target)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    client, manager = client_for(scanner)
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        assert started.wait(timeout=1)
        assert client.get(f"/api/scans/{created['scan_id']}").json()["status"] == "running"
        first = client.get(
            f"/api/scans/{created['scan_id']}/events?after=0"
        ).json()
        assert first["events"][-1]["message"] == "child-one"
        release.wait(timeout=2)
        completed = wait_for_status(client, created["scan_id"], "completed")
        assert completed["status"] == "completed"
    finally:
        release.set()
        manager.shutdown()


def test_concurrent_scan_events_are_isolated_and_ordered() -> None:
    releases = {"a": threading.Event(), "b": threading.Event()}
    started = {"a": threading.Event(), "b": threading.Event()}

    def scanner(target, profile, *, event_callback):
        key = "a" if target == "8.8.8.10" else "b"
        event_callback(ScanEvent("stage", f"{key}-one"))
        started[key].set()
        releases[key].wait(timeout=2)
        event_callback(ScanEvent("info", f"{key}-two"))
        return execution_result(target)

    manager = ScanManager(scanner=scanner, max_workers=2, max_pending=2)
    app = create_app()
    app.dependency_overrides[get_scan_manager] = lambda: manager
    client = AuthenticatedTestClient(app)
    try:
        first = client.post(
            "/api/scans",
            json={"target": "192.0.2.10", "profile": "basic_tcp"},
        ).json()
        second = client.post(
            "/api/scans",
            json={"target": "192.0.2.11", "profile": "basic_tcp"},
        ).json()
        assert started["a"].wait(timeout=1)
        assert started["b"].wait(timeout=1)
        first_events = client.get(
            f"/api/scans/{first['scan_id']}/events?after=0"
        ).json()
        second_events = client.get(
            f"/api/scans/{second['scan_id']}/events?after=0"
        ).json()
        assert [event["message"] for event in first_events["events"]] == [
            "Nmap scan started.",
            "a-one",
        ]
        assert [event["message"] for event in second_events["events"]] == [
            "Nmap scan started.",
            "b-one",
        ]
    finally:
        releases["a"].set()
        releases["b"].set()
        manager.shutdown()


def test_findings_endpoint_returns_rule_evidence() -> None:
    telnet_result = execution_result()
    telnet_result = ScanExecutionResult(
        target=telnet_result.target,
        profile=telnet_result.profile,
        scan=ScanResult(
            target=telnet_result.scan.target,
            ports=(
                PortResult(
                    port=23,
                    protocol="tcp",
                    state="open",
                    service=ServiceMetadata(name="telnet", detection_method="probed", confidence=10),
                ),
            ),
        ),
        stderr=telnet_result.stderr,
        returncode=telnet_result.returncode,
    )
    client, manager = client_for(Mock(return_value=telnet_result))
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        completed = wait_for_status(client, created["scan_id"], "completed")
        response = client.get(f"/api/scans/{completed['scan_id']}/findings")

        assert response.status_code == 200
        finding = response.json()["findings"][0]
        assert finding["rule_id"] == "service.telnet-exposed"
        assert finding["severity"] == "high"
        assert finding["verification_status"] == "requires_verification"
        assert "tcp/23" in finding["evidence"]
    finally:
        manager.shutdown()


def test_invalid_targets_are_rejected_and_valid_targets_are_accepted() -> None:
    client, manager = client_for()
    try:
        capability = issue_capability(secrets.token_urlsafe(24), Settings.from_environment())
        auth_header = {"Authorization": f"Bearer {capability}"}
        assert client.post("/api/scans", json={"target": "http://127.0.0.1", "profile": "basic_tcp"}, headers=auth_header).status_code == 422
        assert client.post("/api/scans", json={"target": "example.test", "profile": "basic_tcp"}).status_code == 202
        assert client.post("/api/scans", json={"target": "192.0.2.1", "profile": "basic_tcp"}, headers=auth_header).status_code == 403
        assert client.post("/api/scans", json={"target": "127.0.0.1", "profile": "unknown"}).status_code == 422
    finally:
        manager.shutdown()


def test_failure_and_unknown_scan_responses() -> None:
    scanner = Mock(side_effect=TimeoutError("execution timed out"))
    client, manager = client_for(scanner)
    try:
        created = client.post("/api/scans", json={"target": "127.0.0.1", "profile": "basic_tcp"}).json()
        failed = wait_for_status(client, created["scan_id"], "failed")
        assert failed["error"] == "execution timed out"
        assert client.get(f"/api/scans/{created['scan_id']}/ports").status_code == 409
        assert client.get(f"/api/scans/{created['scan_id']}/findings").status_code == 409
        assert client.get(f"/api/scans/{created['scan_id']}/report").status_code == 409
        assert client.get("/api/scans/missing").status_code == 404
        assert client.get("/api/scans/missing/report").status_code == 404
    finally:
        manager.shutdown()


def test_timeout_status_contains_scan_id_and_timeout_explanation() -> None:
    client, manager = client_for(Mock(side_effect=NmapTimeoutError(
        "Nmap service_detection scan exceeded the 300-second timeout."
    )))
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "service_detection"},
        ).json()
        failed = wait_for_status(client, created["scan_id"], "failed")
        assert failed["error"] == (
            f"Scan {created['scan_id']} timed out: "
            "Nmap service_detection scan exceeded the 300-second timeout."
        )
        assert client.get(f"/api/scans/{created['scan_id']}/ports").status_code == 409
    finally:
        manager.shutdown()


def test_real_timeout_cleanup_fails_scan_and_releases_queue_slot() -> None:
    child_processes = []
    calls = 0

    def scanner(target, profile):
        nonlocal calls
        calls += 1
        if calls == 1:
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            child_processes.append(child)
            _terminate_process(child)
            raise NmapTimeoutError(
                "Nmap basic_tcp scan exceeded the 1-second timeout."
            )
        return execution_result(target)

    client, manager = client_for(scanner, max_pending=2)
    try:
        first = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        second = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        failed = wait_for_status(client, first["scan_id"], "failed")
        completed = wait_for_status(client, second["scan_id"], "completed")
        assert "timed out" in failed["error"]
        assert completed["scan_id"] == second["scan_id"]
        assert all(child.poll() is not None for child in child_processes)
    finally:
        for child in child_processes:
            if child.poll() is None:
                child.kill()
                child.wait()
        manager.shutdown()


def test_scan_events_use_cursor_and_are_bounded() -> None:
    release = threading.Event()

    def scanner(target, profile, *, event_callback):
        for index in range(5):
            event_callback(
                ScanEvent(
                    event_type="info",
                    message=f"event {index}",
                )
            )
        release.wait(timeout=2)
        return execution_result(target)

    manager = ScanManager(
        scanner=scanner,
        max_workers=1,
        max_pending=1,
        max_events=3,
    )
    app = create_app()
    app.dependency_overrides[get_scan_manager] = lambda: manager
    client = AuthenticatedTestClient(app)
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        for _ in range(20):
            events = client.get(
                f"/api/scans/{created['scan_id']}/events?after=0"
            ).json()
            if len(events["events"]) == 3:
                break
            time.sleep(0.01)
        assert [event["message"] for event in events["events"]] == [
            "event 2",
            "event 3",
            "event 4",
        ]
        cursor = events["next_sequence"]
        assert client.get(
            f"/api/scans/{created['scan_id']}/events?after={cursor}"
        ).json()["events"] == []
    finally:
        release.set()
        manager.shutdown()


def test_report_formats_share_completed_scan_data() -> None:
    client, manager = client_for()
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        completed = wait_for_status(client, created["scan_id"], "completed")
        scan_id = completed["scan_id"]

        html = client.get(f"/api/scans/{scan_id}/report?format=html")
        report_json = client.get(f"/api/scans/{scan_id}/report?format=json")
        pdf = client.get(f"/api/scans/{scan_id}/report?format=pdf")
        unsupported = client.get(f"/api/scans/{scan_id}/report?format=csv")

        assert html.status_code == report_json.status_code == pdf.status_code == 200
        assert html.headers["content-type"] == "text/html; charset=utf-8"
        assert report_json.headers["content-type"] == "application/json"
        assert pdf.headers["content-type"] == "application/pdf"
        assert html.headers["content-disposition"].endswith(".html\"")
        assert report_json.headers["content-disposition"].endswith(".json\"")
        assert pdf.headers["content-disposition"].endswith(".pdf\"")
        payload = json.loads(report_json.text)
        assert payload["scan"]["scan_id"] == scan_id
        assert payload["summary"]["open_ports"] == completed["summary"]["open_ports"]
        assert payload["ports"][0]["service"] == "ssh"
        assert pdf.content.startswith(b"%PDF")
        assert unsupported.status_code == 400
    finally:
        manager.shutdown()


def test_queue_capacity_returns_429() -> None:
    started = threading.Event()
    release = threading.Event()

    def block(target, profile):
        started.set()
        release.wait(timeout=2)
        return execution_result(target)
    client, manager = client_for(block, max_pending=1)
    try:
        first = client.post("/api/scans", json={"target": "127.0.0.1", "profile": "basic_tcp"})
        assert started.wait(timeout=1)
        second = client.post("/api/scans", json={"target": "127.0.0.1", "profile": "basic_tcp"})
        assert first.status_code == 202
        assert second.status_code == 429
    finally:
        release.set()
        manager.shutdown()


def test_cors_default_origin() -> None:
    client, manager = client_for()
    try:
        response = client.options(
            "/api/scans",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    finally:
        manager.shutdown()


def test_concurrent_status_reads_are_consistent() -> None:
    client, manager = client_for()
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        scan_id = created["scan_id"]
        with ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(
                executor.map(
                    lambda _: client.get(f"/api/scans/{scan_id}").json(),
                    range(24),
                )
            )
        assert all(response["scan_id"] == scan_id for response in responses)
        assert all(
            response["status"]
            in {ScanStatus.QUEUED, ScanStatus.RUNNING, ScanStatus.COMPLETED}
            for response in responses
        )
    finally:
        manager.shutdown()


def test_progress_updates_are_exposed_while_scan_is_running() -> None:
    progress_seen = threading.Event()
    release = threading.Event()

    def scanner(target, profile, *, progress_callback):
        progress_callback(
            ProgressUpdate(
                stage="connect scan",
                percent=37.5,
                elapsed_seconds=2.0,
                estimated_remaining_seconds=4.0,
                message="Stats: About 37.50% done",
            )
        )
        progress_seen.set()
        release.wait(timeout=2)
        return execution_result(target)

    manager = ScanManager(scanner=scanner, max_workers=1, max_pending=2)
    app = create_app()
    app.dependency_overrides[get_scan_manager] = lambda: manager
    client = AuthenticatedTestClient(app)
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        assert progress_seen.wait(timeout=1)
        response = client.get(f"/api/scans/{created['scan_id']}")
        assert response.json()["status"] == "running"
        progress = response.json()["progress"]
        assert progress == {
            "stage": "connect scan",
            "percent": 37.5,
            "elapsed_seconds": progress["elapsed_seconds"],
            "estimated_remaining_seconds": 4.0,
            "last_update_at": progress["last_update_at"],
            "message": "Stats: About 37.50% done",
        }
        assert progress["elapsed_seconds"] >= 0
    finally:
        release.set()
        manager.shutdown()


def test_api_progress_can_change_from_indeterminate_to_percentage() -> None:
    progress_seen = threading.Event()
    release = threading.Event()

    def scanner(target, profile, *, progress_callback):
        progress_callback(
            ProgressUpdate(
                stage="Connect Scan",
                percent=None,
                elapsed_seconds=1,
                estimated_remaining_seconds=None,
                message="Waiting for task progress percentage.",
            )
        )
        progress_seen.set()
        release.wait(timeout=2)
        progress_callback(
            ProgressUpdate(
                stage="Connect Scan",
                percent=42,
                elapsed_seconds=2,
                estimated_remaining_seconds=3,
                message="Nmap task progress: Connect Scan 42% complete.",
            )
        )
        return execution_result(target)

    manager = ScanManager(scanner=scanner, max_workers=1, max_pending=1)
    app = create_app()
    app.dependency_overrides[get_scan_manager] = lambda: manager
    client = AuthenticatedTestClient(app)
    try:
        created = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        assert progress_seen.wait(timeout=1)
        first = client.get(f"/api/scans/{created['scan_id']}").json()
        assert first["progress"]["percent"] is None
        release.set()
        for _ in range(20):
            response = client.get(f"/api/scans/{created['scan_id']}").json()
            if response["status"] == "completed":
                break
            time.sleep(0.01)
        assert response["progress"]["percent"] == 42
    finally:
        release.set()
        manager.shutdown()


def test_running_elapsed_time_is_live_and_queued_elapsed_is_zero() -> None:
    first_started = threading.Event()
    release = threading.Event()

    def scanner(target, profile):
        first_started.set()
        release.wait(timeout=2)
        return execution_result(target)

    manager = ScanManager(scanner=scanner, max_workers=1, max_pending=2)
    created_app = create_app()
    created_app.dependency_overrides[get_scan_manager] = lambda: manager
    client = AuthenticatedTestClient(created_app)
    try:
        first = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        assert first_started.wait(timeout=1)
        second = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "profile": "basic_tcp"},
        ).json()
        queued = client.get(f"/api/scans/{second['scan_id']}").json()
        assert queued["status"] == "queued"
        assert queued["progress"]["elapsed_seconds"] == 0.0
        time.sleep(0.1)
        running = client.get(f"/api/scans/{first['scan_id']}").json()
        assert running["status"] == "running"
        assert running["progress"]["elapsed_seconds"] >= 0.1
        release.set()
        assert wait_for_status(client, first["scan_id"], "completed")["status"] == "completed"
        assert wait_for_status(client, second["scan_id"], "completed")["status"] == "completed"
    finally:
        release.set()
        manager.shutdown()


def test_two_scans_run_concurrently_and_third_waits_queued() -> None:
    active = 0
    peak_active = 0
    lock = threading.Lock()
    started = threading.Event()
    release = threading.Event()

    def scanner(target, profile):
        nonlocal active, peak_active
        with lock:
            active += 1
            peak_active = max(peak_active, active)
        started.set()
        release.wait(timeout=2)
        with lock:
            active -= 1
        return execution_result(target)

    manager = ScanManager(scanner=scanner, max_workers=2, max_pending=3)
    try:
        first = manager.submit("127.0.0.1", ScanProfile.QUICK_TCP)
        second = manager.submit("127.0.0.1", ScanProfile.QUICK_TCP)
        third = manager.submit("127.0.0.1", ScanProfile.QUICK_TCP)
        assert started.wait(timeout=1)
        deadline = time.time() + 1
        while time.time() < deadline and peak_active < 2:
            time.sleep(0.01)
        assert peak_active == 2
        assert manager.get(third.scan_id).status is ScanStatus.QUEUED
        release.set()
        assert _wait_manager_status(manager, third.scan_id, ScanStatus.COMPLETED)
    finally:
        release.set()
        manager.shutdown()


def _wait_manager_status(
    manager: ScanManager, scan_id: str, expected: ScanStatus
) -> bool:
    for _ in range(100):
        if manager.get(scan_id).status is expected:
            return True
        time.sleep(0.01)
    return False
