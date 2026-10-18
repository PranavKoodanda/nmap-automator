"""Safe parsing of Nmap XML output."""

from dataclasses import dataclass
import re
from typing import Final
from xml.etree import ElementTree


class NmapXmlError(ValueError):
    """Raised when Nmap XML is malformed or unsafe to parse."""


@dataclass(frozen=True, slots=True)
class ServiceMetadata:
    """Service information reported for a port."""

    name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class PortResult:
    """Normalized result for one reported port."""

    port: int
    protocol: str
    state: str | None
    service: ServiceMetadata


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Normalized Nmap result independent of Nmap's XML representation."""

    target: str | None
    ports: tuple[PortResult, ...]


_EXTERNAL_DTD = re.compile(rb"<!DOCTYPE\s+[^>]*(?:SYSTEM|PUBLIC)", re.IGNORECASE)
_UNSAFE_XML_MARKERS: Final[tuple[bytes, ...]] = (b"<!ENTITY",)
_PORT_STATES: Final[frozenset[str]] = frozenset({"open", "closed", "filtered"})


def parse_nmap_xml(xml_data: str | bytes) -> ScanResult:
    """Parse Nmap XML without resolving external entities or network resources."""

    if isinstance(xml_data, str):
        xml_bytes = xml_data.encode("utf-8")
    elif isinstance(xml_data, bytes):
        xml_bytes = xml_data
    else:
        raise NmapXmlError("Nmap XML must be text or bytes.")

    if (
        any(marker in xml_bytes.upper() for marker in _UNSAFE_XML_MARKERS)
        or _EXTERNAL_DTD.search(xml_bytes) is not None
    ):
        raise NmapXmlError(
            "Nmap XML must not contain external DTD or entity declarations."
        )

    try:
        root = ElementTree.fromstring(xml_bytes)
    except (ElementTree.ParseError, UnicodeDecodeError) as exc:
        raise NmapXmlError("Nmap XML is malformed.") from exc

    if root.tag != "nmaprun":
        raise NmapXmlError("Nmap XML root element must be nmaprun.")

    host = root.find("./host")
    if host is None:
        return ScanResult(target=None, ports=())

    target = _parse_target(host)
    ports: list[PortResult] = []
    for port_element in host.findall("./ports/port"):
        port = _parse_port(port_element)
        if port is not None:
            ports.append(port)

    return ScanResult(target=target, ports=tuple(ports))


def _parse_target(host: ElementTree.Element) -> str | None:
    for address in host.findall("./address"):
        value = address.get("addr")
        if value:
            return value
    return None


def _parse_port(port_element: ElementTree.Element) -> PortResult | None:
    port_value = port_element.get("portid")
    protocol = port_element.get("protocol")
    if port_value is None or protocol is None:
        return None

    try:
        port_number = int(port_value)
    except ValueError:
        return None
    if not 0 <= port_number <= 65535:
        return None

    state_element = port_element.find("./state")
    state = state_element.get("state") if state_element is not None else None
    if state not in _PORT_STATES:
        state = None

    service_element = port_element.find("./service")
    service = ServiceMetadata(
        name=_attribute(service_element, "name"),
        product=_attribute(service_element, "product"),
        version=_attribute(service_element, "version"),
    )
    return PortResult(
        port=port_number,
        protocol=protocol,
        state=state,
        service=service,
    )


def _attribute(element: ElementTree.Element | None, name: str) -> str | None:
    if element is None:
        return None
    value = element.get(name)
    return value if value else None
