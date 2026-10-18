from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import time
from unittest.mock import Mock

from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.app.api.scans import get_scan_manager, get_settings
from backend.app.config import Settings
from backend.app.schemas.scan import ScanStatus
from backend.app.scanner.engine import ScanExecutionResult
from backend.app.scanner.parser import PortResult, ScanResult, ServiceMetadata
from backend.app.scanner.profiles import ScanProfile
from backend.app.services.scan_manager import ScanManager


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


def client_for(scanner=None, *, max_pending: int = 4) -> tuple[TestClient, ScanManager]:
    manager = ScanManager(
        scanner=scanner or Mock(return_value=execution_result()),
        max_workers=1,
        max_pending=max_pending,
    )
    app = create_app()
    app.dependency_overrides[get_scan_manager] = lambda: manager
    app.dependency_overrides[get_settings] = lambda: Settings(
        cors_origins=("http://localhost:5173",),
        allowed_targets=frozenset(),
    )
    return TestClient(app), manager


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
    finally:
        manager.shutdown()


def test_invalid_and_unauthorized_targets_are_rejected() -> None:
    client, manager = client_for()
    try:
        assert client.post("/api/scans", json={"target": "http://127.0.0.1", "profile": "basic_tcp"}).status_code == 422
        assert client.post("/api/scans", json={"target": "192.0.2.1", "profile": "basic_tcp"}).status_code == 403
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
        assert client.get("/api/scans/missing").status_code == 404
    finally:
        manager.shutdown()


def test_queue_capacity_returns_429() -> None:
    blocker = Mock()
    blocker.side_effect = lambda target, profile: time.sleep(0.2) or execution_result(target)
    client, manager = client_for(blocker, max_pending=1)
    try:
        first = client.post("/api/scans", json={"target": "127.0.0.1", "profile": "basic_tcp"})
        second = client.post("/api/scans", json={"target": "127.0.0.1", "profile": "basic_tcp"})
        assert first.status_code == 202
        assert second.status_code == 429
    finally:
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
