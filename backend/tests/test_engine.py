import subprocess
from unittest.mock import Mock, patch

import pytest

from backend.app.scanner.engine import (
    NmapNotFoundError,
    NmapOutputError,
    NmapProcessError,
    NmapTimeoutError,
    run_scan,
)
from backend.app.scanner.profiles import ScanProfile
from backend.app.scanner.validation import TargetValidationError


VALID_XML = (
    "<nmaprun><host><address addr='192.0.2.10'/>"
    "<ports><port protocol='tcp' portid='22'>"
    "<state state='open'/></port></ports></host></nmaprun>"
)


def completed_process(
    *,
    stdout: str = VALID_XML,
    stderr: str = "",
    returncode: int = 0,
) -> Mock:
    process = Mock()
    process.stdout = stdout
    process.stderr = stderr
    process.returncode = returncode
    return process


@pytest.mark.parametrize(
    ("profile", "profile_arguments"),
    [
        (ScanProfile.BASIC_TCP, ("-sT", "-p", "1-1000")),
        (
            ScanProfile.SERVICE_DETECTION,
            ("-sT", "-sV", "--version-light", "-p", "1-1000"),
        ),
    ],
)
def test_run_scan_builds_fixed_arguments_and_parses_xml(
    profile: ScanProfile, profile_arguments: tuple[str, ...]
) -> None:
    process = completed_process()
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="C:\\Nmap\\nmap.exe"),
        patch(
            "backend.app.scanner.engine.subprocess.run",
            return_value=process,
        ) as run,
    ):
        result = run_scan("192.0.2.10", profile, timeout_seconds=30)

    assert result.target == "192.0.2.10"
    assert result.profile is profile
    assert result.scan.ports[0].port == 22
    run.assert_called_once_with(
        [
            "C:\\Nmap\\nmap.exe",
            *profile_arguments,
            "-oX",
            "-",
            "192.0.2.10",
        ],
        shell=False,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_missing_nmap_is_reported() -> None:
    with patch("backend.app.scanner.engine.shutil.which", return_value=None):
        with pytest.raises(NmapNotFoundError, match="not found"):
            run_scan("example.com", ScanProfile.BASIC_TCP)


def test_process_creation_failure_is_reported() -> None:
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch(
            "backend.app.scanner.engine.subprocess.run",
            side_effect=OSError("permission denied"),
        ),
    ):
        with pytest.raises(NmapProcessError, match="Unable to start"):
            run_scan("example.com", ScanProfile.BASIC_TCP)


def test_timeout_is_reported() -> None:
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch(
            "backend.app.scanner.engine.subprocess.run",
            side_effect=subprocess.TimeoutExpired("nmap", 1),
        ),
    ):
        with pytest.raises(NmapTimeoutError, match="timeout"):
            run_scan("example.com", ScanProfile.BASIC_TCP, timeout_seconds=1)


def test_nonzero_exit_status_includes_stderr() -> None:
    process = completed_process(stderr="target is down", returncode=2)
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch("backend.app.scanner.engine.subprocess.run", return_value=process),
    ):
        with pytest.raises(NmapProcessError, match="target is down"):
            run_scan("example.com", ScanProfile.BASIC_TCP)


@pytest.mark.parametrize("stdout", ["", "not xml"])
def test_empty_or_malformed_output_is_reported(stdout: str) -> None:
    process = completed_process(stdout=stdout)
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch("backend.app.scanner.engine.subprocess.run", return_value=process),
    ):
        with pytest.raises(NmapOutputError):
            run_scan("example.com", ScanProfile.BASIC_TCP)


def test_invalid_target_is_rejected_before_process_lookup() -> None:
    with (
        patch("backend.app.scanner.engine.shutil.which") as which,
        patch("backend.app.scanner.engine.subprocess.run") as run,
    ):
        with pytest.raises(TargetValidationError):
            run_scan("127.0.0.1; whoami", ScanProfile.BASIC_TCP)

    which.assert_not_called()
    run.assert_not_called()


def test_unknown_profile_is_rejected_before_process_execution() -> None:
    with (
        patch("backend.app.scanner.engine.shutil.which") as which,
        patch("backend.app.scanner.engine.subprocess.run") as run,
    ):
        with pytest.raises(ValueError, match="Unsupported scan profile"):
            run_scan("example.com", "unsafe_profile")  # type: ignore[arg-type]

    which.assert_not_called()
    run.assert_not_called()


def test_injection_attempt_is_one_target_argument() -> None:
    process = completed_process()
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch(
            "backend.app.scanner.engine.subprocess.run",
            return_value=process,
        ) as run,
    ):
        run_scan("example.com", ScanProfile.BASIC_TCP)

    command = run.call_args.args[0]
    assert command[-1] == "example.com"
    assert all(";" not in argument and "&&" not in argument for argument in command)
