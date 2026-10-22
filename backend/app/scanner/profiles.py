"""Approved Nmap scan profiles."""

from dataclasses import dataclass
from enum import StrEnum
import os


class ScanProfile(StrEnum):
    """Scan profiles supported by the application."""

    QUICK_TCP = "quick_tcp"
    BASIC_TCP = "basic_tcp"
    FULL_TCP = "full_tcp"
    SERVICE_DETECTION = "service_detection"
    COMPREHENSIVE_TCP = "comprehensive_tcp"
    UDP_TOP_100 = "udp_top_100"
    TCP_UDP_COMMON = "tcp_udp_common"


@dataclass(frozen=True, slots=True)
class ProfileDefinition:
    """Immutable Nmap arguments approved for one scan profile."""

    name: ScanProfile
    description: str
    arguments: tuple[str, ...]
    timeout_seconds: int


_PROFILES: dict[ScanProfile, ProfileDefinition] = {
    ScanProfile.QUICK_TCP: ProfileDefinition(
        name=ScanProfile.QUICK_TCP,
        description="Quickly check 100 common TCP ports.",
        arguments=("-sT", "-F"),
        timeout_seconds=60,
    ),
    ScanProfile.BASIC_TCP: ProfileDefinition(
        name=ScanProfile.BASIC_TCP,
        description="Basic TCP port discovery using the existing scan configuration.",
        arguments=("-sT", "-p", "1-1000"),
        timeout_seconds=120,
    ),
    ScanProfile.FULL_TCP: ProfileDefinition(
        name=ScanProfile.FULL_TCP,
        description=(
            "Scan the complete TCP port range with faster timing and limited "
            "retries. Less reliable networks may miss ports."
        ),
        arguments=("-sT", "-T4", "--max-retries", "3", "-p-"),
        timeout_seconds=900,
    ),
    ScanProfile.SERVICE_DETECTION: ProfileDefinition(
        name=ScanProfile.SERVICE_DETECTION,
        description="Identify services and versions using the existing scan configuration.",
        arguments=("-sT", "-sV", "--version-light", "-p", "1-1000"),
        timeout_seconds=300,
    ),
    ScanProfile.COMPREHENSIVE_TCP: ProfileDefinition(
        name=ScanProfile.COMPREHENSIVE_TCP,
        description=(
            "Scan all TCP ports with light service detection, faster timing, "
            "and limited retries. Less reliable networks may miss ports."
        ),
        arguments=(
            "-sT",
            "-sV",
            "--version-light",
            "-T4",
            "--max-retries",
            "3",
            "-p-",
        ),
        timeout_seconds=1200,
    ),
    ScanProfile.UDP_TOP_100: ProfileDefinition(
        name=ScanProfile.UDP_TOP_100,
        description="Check 100 common UDP ports. UDP scans can be slow and may require elevated privileges.",
        arguments=("-sU", "-F"),
        timeout_seconds=600,
    ),
    ScanProfile.TCP_UDP_COMMON: ProfileDefinition(
        name=ScanProfile.TCP_UDP_COMMON,
        description="Scan 100 common ports for both TCP and UDP.",
        arguments=("-sT", "-sU", "-F"),
        timeout_seconds=600,
    ),
}

MAX_TIMEOUT_SECONDS = 1800


def get_profile(profile: ScanProfile) -> ProfileDefinition:
    """Return an approved profile or raise ``ValueError`` for unknown values."""

    try:
        return _PROFILES[profile]
    except KeyError as exc:
        raise ValueError(f"Unsupported scan profile: {profile!r}") from exc


def available_profiles() -> tuple[ProfileDefinition, ...]:
    """Return all approved profiles in stable order."""

    return tuple(_PROFILES.values())


def get_profile_timeout(profile: ScanProfile) -> float:
    """Return a bounded, optionally overridden timeout for one profile."""

    definition = get_profile(profile)
    environment_name = f"NMAP_TIMEOUT_{profile.value.upper()}"
    raw_timeout = os.getenv(environment_name)
    if raw_timeout is None or not raw_timeout.strip():
        return definition.timeout_seconds
    try:
        timeout = int(raw_timeout)
    except ValueError as exc:
        raise ValueError(f"{environment_name} must be a number of seconds.") from exc
    if timeout <= 0 or timeout > MAX_TIMEOUT_SECONDS:
        raise ValueError(
            f"{environment_name} must be greater than zero and at most "
            f"{MAX_TIMEOUT_SECONDS:g} seconds."
        )
    return timeout
