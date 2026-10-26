import shutil

import pytest

from backend.app.scanner.engine import run_scan
from backend.app.scanner.profiles import ScanProfile


NMAP_EXECUTABLE = shutil.which("nmap")


@pytest.mark.skipif(
    NMAP_EXECUTABLE is None,
    reason="Nmap executable is not available on PATH",
)
def test_basic_tcp_scan_against_localhost() -> None:
    result = run_scan(
        "127.0.0.1",
        ScanProfile.BASIC_TCP,
        executable=NMAP_EXECUTABLE or "nmap",
        timeout_seconds=60,
    )

    assert result.returncode == 0
    assert result.target == "127.0.0.1"
    assert result.profile is ScanProfile.BASIC_TCP
    assert result.scan.target == "127.0.0.1"
    assert isinstance(result.scan.ports, tuple)
    for port in result.scan.ports:
        assert 0 <= port.port <= 65535
        assert port.protocol == "tcp"
        assert port.state in {"open", "closed", "filtered", None}
