import ipaddress
import pytest
from scanner.discovery import nmap_runner as n
from scanner.validation import validate_config

XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="srv.lab"/></hostnames><ports>
<port protocol="tcp" portid="9000"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24" method="probed"/></port>
<port protocol="tcp" portid="22"><state state="filtered" reason="no-response"/><service name="ssh" method="table"/></port>
<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/></port></ports>
<os><osmatch name="Linux 5.X" accuracy="95"/></os></host>
<host><status state="down"/><address addr="10.0.0.6" addrtype="ipv4"/></host></nmaprun>"""


def test_parse_states_and_service():
    hosts = n.parse_xml(XML)
    assert len(hosts) == 2 and hosts[0]["hostname"] == "srv.lab" and hosts[0]["os"].startswith("Linux")
    ports = {(p["proto"], p["port"]): p for p in hosts[0]["ports"]}
    assert ports[("tcp", 9000)]["state"] == "open" and ports[("tcp", 9000)]["product"] == "nginx"
    assert ports[("tcp", 22)]["state"] == "filtered" and ports[("tcp", 22)]["method"] == "table"
    assert ports[("udp", 53)]["state"] == "open|filtered"
    assert hosts[1]["status"] == "down"


def test_parse_rejects_garbage():
    with pytest.raises(n.NmapError):
        n.parse_xml("<nmaprun><host>")


def test_args_are_a_list_without_shell_metacharacters():
    cfg = validate_config({})
    a = n.build_port_args(ipaddress.ip_address("10.0.0.5"), "tcp", [22, 80], cfg)
    assert isinstance(a, list) and a[-2:] == ["--", "10.0.0.5"] and "22,80" in a
    assert "-6" in n.build_port_args(ipaddress.ip_address("fe80::1"), "tcp", [22], cfg)
    assert "-sU" in n.build_port_args(ipaddress.ip_address("10.0.0.5"), "udp", [53], cfg)


    def test_os_detection_requires_privileged_nmap(monkeypatch):
        cfg = {"timing": 3, "retries": 1, "host_timeout": 60, "max_rate": 1000,
            "tcp_mode": "connect", "service_detection": False, "os_detection": True}
        monkeypatch.setattr(n.config, "NMAP_PRIVILEGED", False)
        assert "-O" not in n.build_port_args(ipaddress.ip_address("10.0.0.5"), "tcp", [22], cfg)
        monkeypatch.setattr(n.config, "NMAP_PRIVILEGED", True)
        assert "-O" in n.build_port_args(ipaddress.ip_address("10.0.0.5"), "tcp", [22], cfg)
