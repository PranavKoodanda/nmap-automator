"""Safe Nmap subprocess execution."""

from dataclasses import dataclass
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import tempfile
import codecs
import io
from html import unescape
from math import isfinite
from typing import Final
from collections.abc import Callable

from backend.app.scanner.parser import NmapXmlError, ScanResult, parse_nmap_xml
from backend.app.scanner.profiles import (
    MAX_TIMEOUT_SECONDS,
    ScanProfile,
    get_profile,
    get_profile_timeout,
    requires_raw_sockets,
)
from backend.app.scanner.validation import validate_target


DEFAULT_TIMEOUT_SECONDS: Final[float] = 120.0
DEFAULT_EXECUTABLE: Final[str] = "nmap"
TERMINATE_GRACE_SECONDS: Final[float] = 1.0
READER_JOIN_SECONDS: Final[float] = 0.25
LOGGER = logging.getLogger(__name__)


class ScannerError(RuntimeError):
    """Base exception for Nmap execution failures."""


class NmapNotFoundError(ScannerError):
    """Raised when the configured Nmap executable cannot be found."""


class NmapProcessError(ScannerError):
    """Raised when Nmap cannot be started or exits unsuccessfully."""


class NmapTimeoutError(ScannerError):
    """Raised when Nmap exceeds its execution timeout."""


class NmapCancelledError(ScannerError):
    """Raised when a user requests that Nmap stop."""

    def __init__(
        self,
        message: str,
        *,
        partial_result: "ScanExecutionResult | None" = None,
    ) -> None:
        super().__init__(message)
        self.partial_result = partial_result


class NmapOutputError(ScannerError):
    """Raised when Nmap does not return parseable XML output."""


@dataclass(frozen=True, slots=True)
class ProgressUpdate:
    stage: str | None
    percent: float | None
    elapsed_seconds: float
    estimated_remaining_seconds: float | None
    message: str


ProgressCallback = Callable[[ProgressUpdate], None]


@dataclass(frozen=True, slots=True)
class ScanEvent:
    event_type: str
    message: str


EventCallback = Callable[[ScanEvent], None]


@dataclass(frozen=True, slots=True)
class ScanExecutionResult:
    """Parsed result and process metadata from a successful Nmap run."""

    target: str
    profile: ScanProfile
    scan: ScanResult
    stderr: str
    returncode: int


def run_scan(
    target: str,
    profile: ScanProfile,
    *,
    timeout_seconds: float | None = None,
    executable: str = DEFAULT_EXECUTABLE,
    progress_callback: ProgressCallback | None = None,
    event_callback: EventCallback | None = None,
    cancel_event: threading.Event | None = None,
) -> ScanExecutionResult:
    """Run one approved Nmap profile and parse its XML output.

    The target is validated here even when callers have validated it earlier,
    keeping this security-sensitive execution boundary self-contained.
    """

    normalized_target = validate_target(target)
    profile_definition = get_profile(profile)
    if (
        os.getenv("APP_ENV", "development").strip().lower() == "production"
        and requires_raw_sockets(profile)
    ):
        raise NmapProcessError(
            "UDP scanning is unavailable in hosted deployments because it requires raw-socket privileges. "
            "Select a TCP-only profile."
        )
    if timeout_seconds is None:
        timeout_seconds = get_profile_timeout(profile)
    if timeout_seconds <= 0 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"Scan timeout must be greater than zero and at most "
            f"{MAX_TIMEOUT_SECONDS:g} seconds."
        )
    if not executable or executable != executable.strip():
        raise ValueError("Nmap executable must be a non-empty path.")

    executable_path = shutil.which(executable)
    if executable_path is None:
        raise NmapNotFoundError(
            f"Nmap executable was not found: {executable!r}."
        )

    normal_handle, normal_path = tempfile.mkstemp(prefix="nmap-", suffix=".nmap")
    os.close(normal_handle)
    xml_handle, xml_path = tempfile.mkstemp(prefix="nmap-", suffix=".xml")
    os.close(xml_handle)
    arguments = [
        executable_path,
        *profile_definition.arguments,
        # Host discovery may try raw ICMP sockets even for TCP connect scans.
        # Keep -Pn common to every fixed profile, adding it only once.
        *(flag for flag in ("-Pn",) if flag not in profile_definition.arguments),
        "-v",
        "--stats-every",
        "5s",
        "-oN",
        normal_path,
        "-oX",
        xml_path,
        normalized_target,
    ]
    process = None
    started_at = None
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    stderr_size = 0
    reader_errors: list[Exception] = []
    progress_event_seen = threading.Event()
    progress_diagnostic_emitted = False
    last_output_at: float | None = None

    def read_stdout() -> None:
        nonlocal last_output_at
        progress_buffer = ""
        output_buffer = ""
        partial_output_emitted = False
        emitted_partial_length = 0
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            assert process is not None and process.stdout is not None
            while True:
                raw_chunk = _read_pipe_chunk(process.stdout)
                chunk = decoder.decode(raw_chunk, final=not raw_chunk)
                if not chunk:
                    if event_callback is not None and output_buffer:
                        _publish_output_events(
                            output_buffer,
                            event_callback,
                            progress_callback,
                            time.monotonic() - started_at,
                            publish_info=not partial_output_emitted,
                        )
                    return
                last_output_at = time.monotonic()
                stdout_chunks.append(chunk)
                progress_buffer += chunk
                if event_callback is not None:
                    output_buffer += chunk.replace("\r", "\n")
                    complete, output_buffer = _split_complete_lines(output_buffer)
                    for line in complete.splitlines(keepends=True):
                        _publish_output_events(
                            line,
                            event_callback,
                            progress_callback,
                            time.monotonic() - started_at,
                            publish_info=not partial_output_emitted,
                        )
                        partial_output_emitted = False
                        emitted_partial_length = 0
                    if output_buffer:
                        partial_output_emitted = True
                        fragment = output_buffer[emitted_partial_length:]
                        if fragment.strip():
                            event_callback(
                                ScanEvent("output", _sanitize_output_line(fragment))
                            )
                        emitted_partial_length = len(output_buffer)
                progress_buffer = _publish_task_progress(
                    progress_buffer,
                    time.monotonic() - started_at,
                    progress_callback,
                    progress_event_seen,
                )
        except Exception as exc:
            reader_errors.append(exc)

    def read_stderr() -> None:
        nonlocal stderr_size, last_output_at
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        output_buffer = ""
        partial_output_emitted = False
        emitted_partial_length = 0
        try:
            assert process is not None and process.stderr is not None
            while True:
                raw_chunk = _read_pipe_chunk(process.stderr)
                chunk = decoder.decode(raw_chunk, final=not raw_chunk)
                if not chunk:
                    if output_buffer:
                        _consume_stderr_line(
                            output_buffer,
                            publish_info=not partial_output_emitted,
                        )
                    return
                last_output_at = time.monotonic()
                output_buffer += chunk.replace("\r", "\n")
                complete, output_buffer = _split_complete_lines(output_buffer)
                for line in complete.splitlines(keepends=True):
                    _consume_stderr_line(
                        line,
                        publish_info=not partial_output_emitted,
                    )
                    partial_output_emitted = False
                    emitted_partial_length = 0
                if output_buffer and event_callback is not None:
                    partial_output_emitted = True
                    fragment = output_buffer[emitted_partial_length:]
                    if fragment.strip():
                        event_callback(
                            ScanEvent("output", _sanitize_output_line(fragment))
                        )
                    emitted_partial_length = len(output_buffer)

        except Exception as exc:
            reader_errors.append(exc)

    def _consume_stderr_line(line: str, *, publish_info: bool = True) -> None:
        nonlocal stderr_size
        if stderr_size < 65536:
            remaining = 65536 - stderr_size
            stderr_chunks.append(line[:remaining])
            stderr_size += len(line[:remaining])
        update = _parse_progress_line(line, time.monotonic() - started_at)
        if (
            update is None
            and ("stats:" in line.lower() or " done" in line.lower())
        ):
            LOGGER.debug("Unable to parse an Nmap progress statistics line.")
        if event_callback is not None:
            _publish_output_events(
                line,
                event_callback,
                progress_callback if update is None else None,
                time.monotonic() - started_at,
                publish_info=publish_info,
            )
        if update is not None and progress_callback is not None:
            progress_callback(update)

    try:
        popen_options = {
            "shell": False,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
        }
        if os.name == "nt":
            popen_options["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        process = subprocess.Popen(arguments, **popen_options)
        started_at = time.monotonic()
        last_output_at = started_at
        stdout_thread = threading.Thread(
            target=read_stdout, name="nmap-stdout", daemon=True
        )
        stderr_thread = threading.Thread(
            target=read_stderr, name="nmap-stderr", daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()
        deadline = started_at + timeout_seconds
        while True:
            returncode = process.poll()
            if returncode is not None:
                break
            if cancel_event is not None and cancel_event.is_set():
                _terminate_process(process)
                _drain_reader_threads(process, stdout_thread, stderr_thread)
                partial_scan = _read_partial_nmap_xml(xml_path)
                partial_result = ScanExecutionResult(
                    target=normalized_target,
                    profile=profile_definition.name,
                    scan=partial_scan or ScanResult(target=normalized_target, ports=()),
                    stderr="".join(stderr_chunks),
                    returncode=process.returncode if process.returncode is not None else -1,
                )
                raise NmapCancelledError(
                    "Scan stopped by user.", partial_result=partial_result
                )
            if (
                last_output_at is not None
                and time.monotonic() - last_output_at >= 15
                and not progress_diagnostic_emitted
            ):
                LOGGER.info(
                    "No Nmap output observed for 15 seconds while the process is alive."
                )
                progress_diagnostic_emitted = True
                waiting_message = (
                    "Nmap is waiting for output; no scan activity has been "
                    "observed recently."
                )
                if event_callback is not None:
                    event_callback(ScanEvent("info", waiting_message))
                if progress_callback is not None:
                    progress_callback(
                        ProgressUpdate(
                            stage=None,
                            percent=None,
                            elapsed_seconds=round(
                                time.monotonic() - started_at, 3
                            ),
                            estimated_remaining_seconds=None,
                            message=waiting_message,
                        )
                    )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(process)
                _drain_reader_threads(process, stdout_thread, stderr_thread)
                raise NmapTimeoutError(
                    f"Nmap {profile.value} scan exceeded the "
                    f"{timeout_seconds:g}-second timeout."
                )
            time.sleep(min(0.05, remaining))
        try:
            process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            _terminate_process(process)
            raise NmapProcessError(
                f"Nmap {profile.value} exited but could not be reaped."
            )
        _drain_reader_threads(process, stdout_thread, stderr_thread)
    except OSError as exc:
        raise NmapProcessError(f"Unable to start Nmap: {exc}") from exc
    except NmapCancelledError:
        for path in (normal_path, xml_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                LOGGER.warning("Unable to remove temporary Nmap output.")
        raise
    try:
        if process is None:
            raise NmapProcessError("Nmap process was not created.")
        if reader_errors:
            raise NmapProcessError(f"Unable to read Nmap output: {reader_errors[0]}")
        stderr = "".join(stderr_chunks)
        if process.returncode != 0:
            details = stderr.strip()
            lowered_details = details.lower()
            if "raw socket" in lowered_details and any(
                phrase in lowered_details
                for phrase in ("operation not permitted", "permission denied", "not permitted")
            ):
                raise NmapProcessError(
                    "Nmap could not open a raw socket. UDP profiles require raw-socket privileges; "
                    "select a TCP-only profile in this environment."
                )
            message = f"Nmap exited with status {process.returncode}."
            if details:
                message = f"{message} {details}"
            raise NmapProcessError(message)
        try:
            with open(xml_path, encoding="utf-8") as xml_file:
                xml = xml_file.read()
        except OSError as exc:
            raise NmapOutputError("Nmap XML output could not be read.") from exc
        if not xml.strip():
            legacy_xml = "".join(stdout_chunks)
            if legacy_xml.lstrip().startswith("<nmaprun"):
                xml = legacy_xml
        if not xml.strip():
            raise NmapOutputError("Nmap returned empty XML output.")
        try:
            scan = parse_nmap_xml(xml)
        except NmapXmlError as exc:
            raise NmapOutputError(f"Nmap returned invalid XML: {exc}") from exc
        return ScanExecutionResult(
            target=normalized_target,
            profile=profile_definition.name,
            scan=scan,
            stderr=stderr,
            returncode=process.returncode,
        )
    finally:
        for path in (normal_path, xml_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                LOGGER.warning("Unable to remove temporary Nmap output.")


def _terminate_process(process: subprocess.Popen[str]) -> None:
    """Terminate and reap a timed-out process on every supported platform."""

    try:
        process.terminate()
    except OSError:
        pass
    try:
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise NmapProcessError(
                "Nmap could not be terminated and reaped."
            ) from exc


def _close_process_streams(process: subprocess.Popen[str]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                LOGGER.debug("Nmap output stream was already closed.")


def _drain_reader_threads(
    process: subprocess.Popen[str],
    stdout_thread: threading.Thread,
    stderr_thread: threading.Thread,
) -> None:
    """Let readers consume buffered output before closing their pipe handles."""

    stdout_thread.join(timeout=READER_JOIN_SECONDS)
    stderr_thread.join(timeout=READER_JOIN_SECONDS)
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        _close_process_streams(process)
        stdout_thread.join(timeout=READER_JOIN_SECONDS)
        stderr_thread.join(timeout=READER_JOIN_SECONDS)


def _read_partial_nmap_xml(path: str) -> ScanResult | None:
    """Recover only complete port records from an interrupted Nmap XML file."""

    try:
        with open(path, "rb") as xml_file:
            raw_xml = xml_file.read()
    except OSError:
        return None
    if not raw_xml or b"<!ENTITY" in raw_xml.upper():
        return None
    address_match = re.search(rb"<address\b[^>]*(?:/>|>.*?</address>)", raw_xml, re.DOTALL)
    if address_match is None:
        return None
    complete_ports = re.findall(
        rb"<port\b[^>]*/>|<port\b[^>]*>.*?</port\s*>",
        raw_xml,
        re.IGNORECASE | re.DOTALL,
    )
    partial_document = (
        b"<nmaprun><host>"
        + address_match.group(0)
        + b"<ports>"
        + b"".join(complete_ports)
        + b"</ports></host></nmaprun>"
    )
    try:
        return parse_nmap_xml(partial_document)
    except NmapXmlError:
        return None


_PERCENT_RE = re.compile(r"(\d+(?:\.\d+)?)%\s+done", re.IGNORECASE)
_REMAINING_RE = re.compile(
    r"\((?:(\d+):)?(\d+):(\d+)\s+remaining\)", re.IGNORECASE
)
_STAGE_RE = re.compile(r"undergoing\s+([^,.;]+)", re.IGNORECASE)
_TASKPROGRESS_TAG_RE = re.compile(
    r"<taskprogress\b[^>]*?/\s*>", re.IGNORECASE | re.DOTALL
)
_XML_ATTRIBUTE_RE = re.compile(
    r"""([A-Za-z_:][\w:.-]*)\s*=\s*(["'])(.*?)\2""", re.DOTALL
)
_ISO_REMAINING_RE = re.compile(
    r"^PT(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?"
    r"(?:(\d+(?:\.\d+)?)S)?$",
    re.IGNORECASE,
)
_CLOCK_REMAINING_RE = re.compile(
    r"^(?:(\d+):)?(\d+):(\d+(?:\.\d+)?)$"
)
_ANSI_RE = re.compile(r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_PORT_RE = re.compile(
    r"(?:discovered\s+open\s+port\s+)?(\d{1,5})/(tcp|udp)",
    re.IGNORECASE,
)


def _parse_progress_line(line: str, elapsed_seconds: float) -> ProgressUpdate | None:
    if "stats:" not in line.lower() and "done" not in line.lower():
        return None
    percent_match = _PERCENT_RE.search(line)
    remaining_match = _REMAINING_RE.search(line)
    stage_match = _STAGE_RE.search(line)
    remaining = None
    if remaining_match:
        hours = int(remaining_match.group(1) or 0)
        minutes = int(remaining_match.group(2))
        seconds = int(remaining_match.group(3))
        remaining = float(hours * 3600 + minutes * 60 + seconds)
    stage = stage_match.group(1).strip().lower() if stage_match else None
    message = " ".join(line.strip().split())[:240]
    percent = (
        float(percent_match.group(1))
        if percent_match and float(percent_match.group(1)) <= 100
        else None
    )
    return ProgressUpdate(
        stage=stage,
        percent=percent,
        elapsed_seconds=round(max(0.0, elapsed_seconds), 3),
        estimated_remaining_seconds=remaining,
        message=message,
    )


def _publish_task_progress(
    buffer: str,
    elapsed_seconds: float,
    progress_callback: ProgressCallback | None,
    progress_event_seen: threading.Event,
) -> str:
    """Publish complete XML taskprogress tags and retain any partial tag."""

    matches = list(_TASKPROGRESS_TAG_RE.finditer(buffer))
    if not matches:
        return buffer[-4096:] if "<taskprogress" in buffer.lower() else ""
    for match in matches:
        update = _parse_taskprogress_tag(match.group(0), elapsed_seconds)
        if update is not None:
            progress_event_seen.set()
            if progress_callback is not None:
                progress_callback(update)
    return buffer[matches[-1].end():]


def _parse_taskprogress_tag(
    tag: str, elapsed_seconds: float
) -> ProgressUpdate | None:
    attributes = {
        name.lower(): unescape(value)
        for name, _, value in _XML_ATTRIBUTE_RE.findall(tag)
    }
    task = attributes.get("task", "").strip()
    if not task:
        return None
    raw_percent = attributes.get("percent")
    percent = None
    if raw_percent is not None:
        try:
            candidate = float(raw_percent)
        except ValueError:
            candidate = float("nan")
        if isfinite(candidate) and 0 <= candidate <= 100:
            percent = candidate
    remaining = _parse_remaining_seconds(attributes.get("remaining"))
    progress_text = (
        f"{task} {percent:g}% complete" if percent is not None
        else f"{task} progress percentage unavailable"
    )
    if remaining is not None:
        progress_text += f"; approximately {remaining:g}s remaining"
    return ProgressUpdate(
        stage=task,
        percent=percent,
        elapsed_seconds=round(max(0.0, elapsed_seconds), 3),
        estimated_remaining_seconds=remaining,
        message=f"Nmap task progress: {progress_text}.",
    )


def _parse_remaining_seconds(value: str | None) -> float | None:
    if not value:
        return None
    iso_match = _ISO_REMAINING_RE.fullmatch(value.strip())
    if iso_match:
        hours, minutes, seconds = (
            float(part or 0) for part in iso_match.groups()
        )
        return hours * 3600 + minutes * 60 + seconds
    clock_match = _CLOCK_REMAINING_RE.fullmatch(value.strip())
    if clock_match:
        hours, minutes, seconds = (
            float(part or 0) for part in clock_match.groups()
        )
        return hours * 3600 + minutes * 60 + seconds
    return None


def _publish_output_events(
    buffer: str,
    callback: EventCallback,
    progress_callback: ProgressCallback | None = None,
    elapsed_seconds: float = 0.0,
    *,
    publish_info: bool = True,
) -> None:
    """Convert complete normal-output lines into safe activity events."""

    for raw_line in buffer.splitlines():
        line = _sanitize_output_line(raw_line)
        if not line:
            continue
        lowered = line.lower()
        if "scan initiated" in lowered and lowered.startswith("# nmap"):
            if publish_info:
                callback(ScanEvent(event_type="info", message="Nmap scan initiated."))
            _publish_output_stage(
                line, progress_callback, elapsed_seconds, "starting"
            )
            continue
        port_match = _PORT_RE.search(line)
        if port_match and ("open" in lowered or "discovered" in lowered):
            callback(
                ScanEvent(
                    event_type="port_discovered",
                    message=f"Discovered port {port_match.group(1)}/{port_match.group(2).lower()}.",
                )
            )
        elif "stats:" in lowered or "% done" in lowered:
            callback(ScanEvent(event_type="progress", message=line))
            if progress_callback is not None:
                update = _parse_progress_line(line, elapsed_seconds)
                if update is not None:
                    progress_callback(update)
        elif any(word in lowered for word in ("warning", "error", "failed")):
            callback(ScanEvent(event_type="error", message=line[:240]))
        elif any(word in lowered for word in ("initiating", "scanning", "completed")):
            callback(ScanEvent(event_type="stage", message=line[:240]))
            _publish_output_stage(
                line, progress_callback, elapsed_seconds, _stage_from_line(line)
            )
        else:
            if publish_info:
                callback(ScanEvent(event_type="info", message=line[:240]))


def _publish_output_stage(
    line: str,
    progress_callback: ProgressCallback | None,
    elapsed_seconds: float,
    stage: str,
) -> None:
    if progress_callback is None:
        return
    message = (
        "Nmap scan initiated."
        if line.lower().startswith("# nmap") and "scan initiated" in line.lower()
        else " ".join(line.split())[:240]
    )
    progress_callback(
        ProgressUpdate(
            stage=stage,
            percent=None,
            elapsed_seconds=round(max(0.0, elapsed_seconds), 3),
            estimated_remaining_seconds=None,
            message=message,
        )
    )


def _stage_from_line(line: str) -> str:
    normalized = " ".join(line.split()).strip().rstrip(".")
    return normalized.lower()[:80] or "scanning"


def _split_complete_lines(buffer: str) -> tuple[str, str]:
    if "\n" not in buffer and "\r" not in buffer:
        return "", buffer[-8192:]
    last_break = max(buffer.rfind("\n"), buffer.rfind("\r"))
    return buffer[: last_break + 1], buffer[last_break + 1 :]


def _sanitize_output_line(line: str) -> str:
    return " ".join(_ANSI_RE.sub("", line).strip().split())[:240]


def _read_pipe_chunk(stream: object, size: int = 4096) -> bytes:
    """Read currently available pipe data without waiting for a full line."""

    if not isinstance(stream, io.TextIOBase):
        chunk = getattr(stream, "readline")()
        if isinstance(chunk, str):
            return chunk.encode("utf-8", errors="replace")
        return chunk
    buffer = stream.buffer
    read1 = getattr(buffer, "read1", None)
    if callable(read1):
        chunk = read1(size)
    else:
        chunk = getattr(buffer, "read")(size)
    if isinstance(chunk, str):
        return chunk.encode("utf-8", errors="replace")
    return chunk
