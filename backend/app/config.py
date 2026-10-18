"""Environment-backed development safety configuration."""

from dataclasses import dataclass
import ipaddress
import os
import socket

from backend.app.scanner.validation import validate_target


@dataclass(frozen=True, slots=True)
class Settings:
    cors_origins: tuple[str, ...]
    allowed_targets: frozenset[str]

    @classmethod
    def from_environment(cls) -> "Settings":
        origins = tuple(
            origin.strip()
            for origin in os.getenv("FRONTEND_CORS_ORIGINS", "http://localhost:5173").split(",")
            if origin.strip()
        )
        allowlist = frozenset(
            _normalize_allowlist_item(item)
            for item in os.getenv("TARGET_ALLOWLIST", "").split(",")
            if item.strip()
        )
        return cls(cors_origins=origins, allowed_targets=allowlist)

    def is_target_authorized(self, target: str) -> bool:
        normalized = validate_target(target)
        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            try:
                addresses = {
                    ipaddress.ip_address(info[4][0])
                    for info in socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
                }
            except socket.gaierror:
                return False
            if not addresses:
                return False
            if normalized in self.allowed_targets:
                return True
            return all(self._address_allowed(address) for address in addresses)
        return self._address_allowed(address)

    def _address_allowed(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return address.is_loopback or str(address) in self.allowed_targets


def _normalize_allowlist_item(item: str) -> str:
    try:
        return validate_target(item.strip())
    except ValueError:
        return item.strip().lower()
