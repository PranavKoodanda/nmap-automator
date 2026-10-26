"""Validation for scan targets."""

import ipaddress
import re


class TargetValidationError(ValueError):
    """Raised when a target is not a valid IP address or hostname."""


_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_DOTTED_QUAD = re.compile(r"^\d+(?:\.\d+){3}$")


def validate_target(target: str) -> str:
    """Validate and normalize an IPv4 address, IPv6 address, or hostname.

    This validates syntax only. Authorization policy and DNS resolution belong
    to the service layer before a scan is started.
    """

    if not isinstance(target, str):
        raise TargetValidationError("Target must be a string.")

    candidate = target.strip()
    if not candidate or candidate != target:
        raise TargetValidationError("Target must not be empty or contain whitespace.")

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    if _DOTTED_QUAD.fullmatch(candidate):
        raise TargetValidationError("Target must be a valid IP address or hostname.")

    hostname = candidate[:-1] if candidate.endswith(".") else candidate
    if len(hostname) > 253 or not hostname:
        raise TargetValidationError("Target must be a valid IP address or hostname.")

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError("Target must be a valid hostname.") from exc

    if len(ascii_hostname) > 253 or any(
        not _HOSTNAME_LABEL.fullmatch(label) for label in ascii_hostname.split(".")
    ):
        raise TargetValidationError("Target must be a valid hostname.")

    return ascii_hostname.lower()


def validate_fqdn(target: str) -> str:
    """Normalize a public, fully qualified hostname; reject IPs and local names."""
    normalized = validate_target(target)
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        raise TargetValidationError("A fully qualified domain name is required; IP addresses are not accepted.")
    if "." not in normalized or normalized.endswith("."):
        raise TargetValidationError("Enter a fully qualified domain name with at least two labels.")
    return normalized
