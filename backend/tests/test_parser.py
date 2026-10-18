import pytest

from backend.app.scanner.parser import NmapXmlError, parse_nmap_xml


XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parser_normalizes_port_states_and_service_metadata() -> None:
    result = parse_nmap_xml(XML)

    assert result.target == "192.0.2.10"
    assert [(port.port, port.state) for port in result.ports] == [
        (22, "open"),
        (80, "closed"),
        (443, "filtered"),
    ]
    assert result.ports[0].service.name == "ssh"
    assert result.ports[0].service.product == "OpenSSH"
    assert result.ports[0].service.version == "9.6"
    assert result.ports[0].service.detection_method == "probed"
    assert result.ports[0].service.confidence == 10
    assert result.ports[1].service.product is None
    assert result.ports[2].service.name is None


def test_parser_preserves_table_inference_and_rejects_invalid_metadata() -> None:
    result = parse_nmap_xml(
        "<nmaprun><host><ports>"
        "<port protocol='tcp' portid='23'><state state='open'/>"
        "<service name='telnet' method='table' conf='3'/></port>"
        "<port protocol='tcp' portid='21'><state state='open'/>"
        "<service name='ftp' method='mystery' conf='not-a-number'/></port>"
        "</ports></host></nmaprun>"
    )

    assert result.ports[0].service.detection_method == "table"
    assert result.ports[0].service.confidence == 3
    assert result.ports[1].service.detection_method is None
    assert result.ports[1].service.confidence is None


def test_parser_preserves_unknown_state_as_unavailable() -> None:
    result = parse_nmap_xml(
        "<nmaprun><host><ports><port protocol='tcp' portid='1'>"
        "<state state='open|filtered'/></port></ports></host></nmaprun>"
    )

    assert result.ports[0].state is None


@pytest.mark.parametrize(
    "xml_data",
    [
        "",
        "<nmaprun>",
        "<not-nmaprun />",
        b"<!DOCTYPE nmaprun SYSTEM 'http://example.invalid/nmap.dtd'>"
        b"<nmaprun />",
        b"<!ENTITY xxe SYSTEM 'file:///secret'><nmaprun />",
    ],
)
def test_parser_rejects_malformed_or_unsafe_xml(xml_data: str | bytes) -> None:
    with pytest.raises(NmapXmlError):
        parse_nmap_xml(xml_data)


def test_parser_ignores_ports_with_missing_required_attributes() -> None:
    result = parse_nmap_xml(
        "<nmaprun><host><ports>"
        "<port protocol='tcp'><state state='open'/></port>"
        "<port protocol='tcp' portid='not-a-port'/>"
        "<port protocol='tcp' portid='70000'/>"
        "<port protocol='tcp' portid='53'><state/></port>"
        "</ports></host></nmaprun>"
    )

    assert len(result.ports) == 1
    assert result.ports[0].port == 53
    assert result.ports[0].state is None
