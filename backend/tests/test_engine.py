import sys
import subprocess
import sys
import threading
import time
from unittest.mock import Mock, patch

import pytest

from backend.app.scanner.engine import (
    NmapNotFoundError,
    NmapOutputError,
    NmapProcessError,
    NmapTimeoutError,
    _parse_progress_line,
    _parse_taskprogress_tag,
    _publish_output_events,
    _publish_task_progress,
    _terminate_process,
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
    process.stdout.readline.side_effect = [stdout, ""]
    process.stderr.readline.side_effect = [stderr, ""]
    process.returncode = returncode
    return process


@pytest.mark.parametrize(
    ("profile", "profile_arguments"),
    [
        (ScanProfile.QUICK_TCP, ("-sT", "-F")),
        (ScanProfile.BASIC_TCP, ("-sT", "-p", "1-1000")),
        (ScanProfile.FULL_TCP, ("-sT", "-T4", "--max-retries", "3", "-p-")),
        (
            ScanProfile.SERVICE_DETECTION,
            ("-sT", "-sV", "--version-light", "-p", "1-1000"),
        ),
        (
            ScanProfile.COMPREHENSIVE_TCP,
            (
                "-sT",
                "-sV",
                "--version-light",
                "-T4",
                "--max-retries",
                "3",
                "-p-",
            ),
        ),
        (ScanProfile.UDP_TOP_100, ("-sU", "-F")),
        (ScanProfile.TCP_UDP_COMMON, ("-sT", "-sU", "-F")),
    ],
)
def test_run_scan_builds_fixed_arguments_and_parses_xml(
    profile: ScanProfile, profile_arguments: tuple[str, ...]
) -> None:
    process = completed_process()
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="C:\\Nmap\\nmap.exe"),
        patch(
            "backend.app.scanner.engine.subprocess.Popen",
            return_value=process,
        ) as run,
    ):
        result = run_scan("192.0.2.10", profile, timeout_seconds=30)

    assert result.target == "192.0.2.10"
    assert result.profile is profile
    assert result.scan.ports[0].port == 22
    run.assert_called_once()
    command = run.call_args.args[0]
    assert command[: len(profile_arguments) + 1] == [
        "C:\\Nmap\\nmap.exe",
        *profile_arguments,
    ]
    assert command[len(profile_arguments) + 1:] == [
        "-v",
        "--stats-every",
        "5s",
        "-oN",
        command[-4],
        "-oX",
        command[-2],
        "192.0.2.10",
    ]
    assert command[-2].endswith(".xml")
    assert command[-4].endswith(".nmap")
    assert run.call_args.kwargs == {
        "shell": False,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    }


def test_normal_output_publishes_stats_stages_and_errors() -> None:
    events = []
    updates = []
    _publish_output_events(
        "Initiating TCP Connect Scan.\n"
        "Stats: About 42.50% done; 1 undergoing Connect Scan\n"
        "Warning: target did not respond.\n"
        "Completed TCP Connect Scan.\n",
        events.append,
        updates.append,
        7,
    )

    assert [event.event_type for event in events] == [
        "stage",
        "progress",
        "error",
        "stage",
    ]
    assert events[1].message.startswith("Stats: About 42.50% done")
    assert next(update for update in updates if update.percent is not None).percent == 42.5
    assert updates[-1].stage == "completed tcp connect scan"


def test_run_scan_publishes_unterminated_output_while_child_is_alive() -> None:
    partial_seen = threading.Event()
    finished = threading.Event()
    events = []
    real_popen = subprocess.Popen
    child_source = (
        "import sys,time; "
        "sys.stdout.write('partial output'); sys.stdout.flush(); "
        "time.sleep(0.6); sys.stdout.write('\\r'); sys.stdout.flush(); "
        "open(sys.argv[1], 'w', encoding='utf-8').write("
        + repr(VALID_XML)
        + "); time.sleep(0.4)"
    )

    def child_process(command, *args, **kwargs):
        xml_path = command[command.index("-oX") + 1]
        return real_popen(
            [sys.executable, "-u", "-c", child_source, xml_path],
            *args,
            **kwargs,
        )

    def on_event(event):
        events.append(event)
        if event.event_type == "output" and "partial output" in event.message:
            partial_seen.set()

    def execute():
        try:
            with (
                patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
                patch(
                    "backend.app.scanner.engine.subprocess.Popen",
                    side_effect=child_process,
                ),
            ):
                run_scan(
                    "127.0.0.1",
                    ScanProfile.BASIC_TCP,
                    timeout_seconds=5,
                    event_callback=on_event,
                )
        finally:
            finished.set()

    worker = threading.Thread(target=execute)
    worker.start()
    try:
        assert partial_seen.wait(timeout=2)
        assert not finished.is_set()
        assert any(event.message == "partial output" for event in events)
    finally:
        worker.join(timeout=3)
    assert finished.is_set()


def test_missing_nmap_is_reported() -> None:
    with patch("backend.app.scanner.engine.shutil.which", return_value=None):
        with pytest.raises(NmapNotFoundError, match="not found"):
            run_scan("example.com", ScanProfile.BASIC_TCP)


def test_process_creation_failure_is_reported() -> None:
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch(
            "backend.app.scanner.engine.subprocess.Popen",
            side_effect=OSError("permission denied"),
        ),
    ):
        with pytest.raises(NmapProcessError, match="Unable to start"):
            run_scan("example.com", ScanProfile.BASIC_TCP)


def test_timeout_is_reported() -> None:
    timeout_process = Mock()
    timeout_process.poll.return_value = None
    timeout_process.stdout.readline.side_effect = ["", ""]
    timeout_process.stderr.readline.side_effect = ["", ""]
    timeout_process.wait.return_value = 0
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch(
            "backend.app.scanner.engine.subprocess.Popen",
            return_value=timeout_process,
        ),
    ):
        with pytest.raises(NmapTimeoutError, match="timeout"):
            run_scan("example.com", ScanProfile.BASIC_TCP, timeout_seconds=1)
    timeout_process.terminate.assert_called_once_with()
    timeout_process.wait.assert_called()


def test_real_child_process_is_terminated_within_bounded_time() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    started = time.monotonic()
    try:
        _terminate_process(child)
        elapsed = time.monotonic() - started
        assert child.poll() is not None
        assert elapsed < 3
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_run_scan_timeout_terminates_real_child_process() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    started = time.monotonic()
    try:
        with (
            patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
            patch(
                "backend.app.scanner.engine.subprocess.Popen",
                return_value=child,
            ),
        ):
            with pytest.raises(NmapTimeoutError, match="timeout"):
                run_scan(
                    "127.0.0.1",
                    ScanProfile.BASIC_TCP,
                    timeout_seconds=0.1,
                )
        assert child.poll() is not None
        assert time.monotonic() - started < 3
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_progress_line_parses_stage_and_percentage() -> None:
    update = _parse_progress_line(
        "Stats: About 42.50% done; 1 undergoing Connect Scan",
        12.5,
    )

    assert update is not None
    assert update.stage == "connect scan"
    assert update.percent == 42.5
    assert update.elapsed_seconds == 12.5
    assert update.estimated_remaining_seconds is None


def test_progress_line_without_percentage_is_indeterminate() -> None:
    update = _parse_progress_line(
        "Stats: 0:00:05 elapsed; 1 undergoing Service Scan",
        5,
    )

    assert update is not None
    assert update.stage == "service scan"
    assert update.percent is None
    assert update.estimated_remaining_seconds is None


def test_malformed_or_out_of_range_progress_is_indeterminate() -> None:
    update = _parse_progress_line(
        "Stats: About 140% done; 1 undergoing Connect Scan",
        5,
    )

    assert update is not None
    assert update.percent is None


def test_taskprogress_xml_parses_percentage_and_remaining() -> None:
    update = _parse_taskprogress_tag(
        '<taskprogress task="Connect Scan" percent="12.50" '
        'remaining="PT1M2.5S" />',
        4.25,
    )

    assert update is not None
    assert update.stage == "Connect Scan"
    assert update.percent == 12.5
    assert update.estimated_remaining_seconds == 62.5
    assert update.elapsed_seconds == 4.25


def test_taskprogress_chunks_publish_without_changing_xml_buffer() -> None:
    updates = []
    seen = threading.Event()
    buffer = _publish_task_progress(
        '<nmaprun><taskprogress task="Ping Scan" percent="0',
        1,
        updates.append,
        seen,
    )
    buffer = _publish_task_progress(
        buffer + '.00" remaining="PT10S" />',
        2,
        updates.append,
        seen,
    )

    assert updates[0].percent == 0
    assert updates[0].stage == "Ping Scan"
    assert updates[0].estimated_remaining_seconds == 10
    assert seen.is_set()
    assert buffer == ""


def test_multiple_taskprogress_events_publish_each_stage() -> None:
    updates = []
    seen = threading.Event()
    buffer = (
        '<taskprogress task="Ping Scan" percent="10" remaining="PT9S" />'
        '<taskprogress task="Connect Scan" percent="55" remaining="PT4S" />'
    )

    remainder = _publish_task_progress(
        buffer,
        3,
        updates.append,
        seen,
    )

    assert remainder == ""
    assert [(item.stage, item.percent) for item in updates] == [
        ("Ping Scan", 10),
        ("Connect Scan", 55),
    ]


def test_taskprogress_events_are_read_from_stdout_and_xml_is_preserved() -> None:
    xml = (
        '<nmaprun><taskprogress task="Connect Scan" percent="25.00" '
        'remaining="PT5S" />'
        "<host><address addr='192.0.2.10'/>"
        "<ports><port protocol='tcp' portid='22'>"
        "<state state='open'/></port></ports></host></nmaprun>"
    )
    process = completed_process(stdout=xml)
    updates = []
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch(
            "backend.app.scanner.engine.subprocess.Popen",
            return_value=process,
        ),
    ):
        result = run_scan(
            "192.0.2.10",
            ScanProfile.BASIC_TCP,
            progress_callback=updates.append,
        )

    assert result.scan.ports[0].port == 22
    assert updates[0].percent == 25
    assert updates[0].estimated_remaining_seconds == 5


@pytest.mark.parametrize("raw_percent", ["-1", "101", "not-a-number"])
def test_taskprogress_invalid_percentage_is_null(raw_percent: str) -> None:
    update = _parse_taskprogress_tag(
        f'<taskprogress task="Service Scan" percent="{raw_percent}" />',
        1,
    )

    assert update is not None
    assert update.percent is None


@pytest.mark.parametrize(
    ("profile", "expected_timeout"),
    [
        (ScanProfile.QUICK_TCP, 60),
        (ScanProfile.BASIC_TCP, 120),
        (ScanProfile.FULL_TCP, 900),
        (ScanProfile.SERVICE_DETECTION, 300),
        (ScanProfile.COMPREHENSIVE_TCP, 1200),
        (ScanProfile.UDP_TOP_100, 600),
        (ScanProfile.TCP_UDP_COMMON, 600),
    ],
)
def test_profile_default_timeout_is_applied(
    profile: ScanProfile, expected_timeout: float
) -> None:
    process = completed_process()
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch(
            "backend.app.scanner.engine.subprocess.Popen",
            return_value=process,
        ),
    ):
        run_scan("example.com", profile)
    from backend.app.scanner.profiles import get_profile_timeout

    assert get_profile_timeout(profile) == expected_timeout


def test_nonzero_exit_status_includes_stderr() -> None:
    process = completed_process(stderr="target is down", returncode=2)
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch("backend.app.scanner.engine.subprocess.Popen", return_value=process),
    ):
        with pytest.raises(NmapProcessError, match="target is down"):
            run_scan("example.com", ScanProfile.BASIC_TCP)


@pytest.mark.parametrize("stdout", ["", "not xml"])
def test_empty_or_malformed_output_is_reported(stdout: str) -> None:
    process = completed_process(stdout=stdout)
    with (
        patch("backend.app.scanner.engine.shutil.which", return_value="nmap"),
        patch("backend.app.scanner.engine.subprocess.Popen", return_value=process),
    ):
        with pytest.raises(NmapOutputError):
            run_scan("example.com", ScanProfile.BASIC_TCP)


def test_invalid_target_is_rejected_before_process_lookup() -> None:
    with (
        patch("backend.app.scanner.engine.shutil.which") as which,
        patch("backend.app.scanner.engine.subprocess.Popen") as run,
    ):
        with pytest.raises(TargetValidationError):
            run_scan("127.0.0.1; whoami", ScanProfile.BASIC_TCP)

    which.assert_not_called()
    run.assert_not_called()


def test_unknown_profile_is_rejected_before_process_execution() -> None:
    with (
        patch("backend.app.scanner.engine.shutil.which") as which,
        patch("backend.app.scanner.engine.subprocess.Popen") as run,
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
            "backend.app.scanner.engine.subprocess.Popen",
            return_value=process,
        ) as run,
    ):
        run_scan("example.com", ScanProfile.BASIC_TCP)

    command = run.call_args.args[0]
    assert command[-1] == "example.com"
    assert all(";" not in argument and "&&" not in argument for argument in command)
