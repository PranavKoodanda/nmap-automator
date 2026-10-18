"""Approved Nmap scan profiles."""

from dataclasses import dataclass
from enum import StrEnum


class ScanProfile(StrEnum):
    """Scan profiles supported by the application."""

    BASIC_TCP = "basic_tcp"
    SERVICE_DETECTION = "service_detection"


@dataclass(frozen=True, slots=True)
class ProfileDefinition:
    """Immutable Nmap arguments approved for one scan profile."""

    name: ScanProfile
    description: str
    arguments: tuple[str, ...]


_PROFILES: dict[ScanProfile, ProfileDefinition] = {
    ScanProfile.BASIC_TCP: ProfileDefinition(
        name=ScanProfile.BASIC_TCP,
        description="TCP connect scan of the standard ports.",
        arguments=("-sT", "-p", "1-1000"),
    ),
    ScanProfile.SERVICE_DETECTION: ProfileDefinition(
        name=ScanProfile.SERVICE_DETECTION,
        description="TCP connect scan with light service and version detection.",
        arguments=("-sT", "-sV", "--version-light", "-p", "1-1000"),
    ),
}


def get_profile(profile: ScanProfile) -> ProfileDefinition:
    """Return an approved profile or raise ``ValueError`` for unknown values."""

    try:
        return _PROFILES[profile]
    except KeyError as exc:
        raise ValueError(f"Unsupported scan profile: {profile!r}") from exc


def available_profiles() -> tuple[ProfileDefinition, ...]:
    """Return all approved profiles in stable order."""

    return tuple(_PROFILES.values())
