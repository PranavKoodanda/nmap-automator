"""Safe Nmap subprocess execution."""

from dataclasses import dataclass
import shutil
import subprocess
from typing import Final

from backend.app.scanner.parser import NmapXmlError, ScanResult, parse_nmap_xml
from backend.app.scanner.profiles import ScanProfile, get_profile
from backend.app.scanner.validation import validate_target


DEFAULT_TIMEOUT_SECONDS: Final[float] = 120.0
DEFAULT_EXECUTABLE: Final[str] = "nmap"


class ScannerError(RuntimeError):
    """Base exception for Nmap execution failures."""


class NmapNotFoundError(ScannerError):
    """Raised when the configured Nmap executable cannot be found."""


class NmapProcessError(ScannerError):
    """Raised when Nmap cannot be started or exits unsuccessfully."""


class NmapTimeoutError(ScannerError):
    """Raised when Nmap exceeds its execution timeout."""


class NmapOutputError(ScannerError):
    """Raised when Nmap does not return parseable XML output."""


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
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    executable: str = DEFAULT_EXECUTABLE,
) -> ScanExecutionResult:
    """Run one approved Nmap profile and parse its XML output.

    The target is validated here even when callers have validated it earlier,
    keeping this security-sensitive execution boundary self-contained.
    """

    normalized_target = validate_target(target)
    profile_definition = get_profile(profile)
    if timeout_seconds <= 0:
        raise ValueError("Scan timeout must be greater than zero.")
    if not executable or executable != executable.strip():
        raise ValueError("Nmap executable must be a non-empty path.")

    executable_path = shutil.which(executable)
    if executable_path is None:
        raise NmapNotFoundError(
            f"Nmap executable was not found: {executable!r}."
        )

    arguments = [
        executable_path,
        *profile_definition.arguments,
        "-oX",
        "-",
        normalized_target,
    ]
    try:
        completed = subprocess.run(
            arguments,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapTimeoutError(
            f"Nmap scan exceeded the {timeout_seconds:g}-second timeout."
        ) from exc
    except OSError as exc:
        raise NmapProcessError(f"Unable to start Nmap: {exc}") from exc

    if completed.returncode != 0:
        details = completed.stderr.strip()
        message = f"Nmap exited with status {completed.returncode}."
        if details:
            message = f"{message} {details}"
        raise NmapProcessError(message)

    if not completed.stdout or not completed.stdout.strip():
        raise NmapOutputError("Nmap returned empty XML output.")

    try:
        scan = parse_nmap_xml(completed.stdout)
    except NmapXmlError as exc:
        raise NmapOutputError(f"Nmap returned invalid XML: {exc}") from exc

    return ScanExecutionResult(
        target=normalized_target,
        profile=profile_definition.name,
        scan=scan,
        stderr=completed.stderr,
        returncode=completed.returncode,
    )
