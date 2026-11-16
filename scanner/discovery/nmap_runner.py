"""Safe nmap integration: argument arrays only, no shell, hard timeouts, XML parsing."""
import ipaddress
import subprocess
import xml.etree.ElementTree as ET

from .. import config

TIMING = {0: "-T0", 1: "-T1", 2: "-T2", 3: "-T3", 4: "-T4"}


class NmapError(RuntimeError):
    pass


def available():
    return bool(config.NMAP_PATH)


def _common(cfg, family):
    a = [config.NMAP_PATH, "-oX", "-", "-n", "--reason", TIMING[cfg["timing"]],
         "--max-retries", str(cfg["retries"]), "--host-timeout", f"{cfg['host_timeout']}s",
         "--max-rate", str(cfg["max_rate"])]
    if family == 6:
        a.append("-6")
    return a


def build_discovery_args(spec, cfg):
    net = ipaddress.ip_network(spec, strict=False)
    return _common(cfg, net.version) + ["-sn", "--", str(net)]


def build_port_args(address, proto, ports, cfg):
    """ports: list[int] (already validated). address: ipaddress object."""
    ip = ipaddress.ip_address(str(address))
    a = _common(cfg, ip.version) + ["-Pn"]
    if proto == "tcp":
        a.append("-sS" if cfg["tcp_mode"] == "syn" and config.NMAP_PRIVILEGED else "-sT")
        if config.NMAP_PRIVILEGED:
            a.append("--privileged")
    else:
        a.append("-sU")
        a.append("--privileged") if config.NMAP_PRIVILEGED else None
    a += ["-p", ",".join(str(p) for p in ports)]
    if cfg.get("service_detection"):
        a += ["-sV", "--version-intensity", "5"]
    if cfg.get("os_detection") and config.NMAP_PRIVILEGED and proto == "tcp":
        a.append("-O")
    return [x for x in a if x] + ["--", str(ip)]


def run(args, timeout):
    if not available():
        raise NmapError("nmap not installed")
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, shell=False)
    except subprocess.TimeoutExpired:
        raise NmapError(f"nmap exceeded {timeout}s hard timeout")
    if p.returncode != 0 and not p.stdout.strip():
        raise NmapError((p.stderr or "nmap failed").strip()[:400])
    return p.stdout, p.stderr


def parse_xml(xml_text):
    """Return list of host dicts. Tolerates truncated output by returning what parsed."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise NmapError(f"cannot parse nmap XML: {e}")
    hosts = []
    for h in root.findall("host"):
        st = h.find("status")
        addr = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a
        if addr is None:
            continue
        hn = h.find("hostnames/hostname")
        osm = h.find("os/osmatch")
        host = {
            "address": addr.get("addr"), "family": 6 if addr.get("addrtype") == "ipv6" else 4,
            "status": st.get("state") if st is not None else "unknown",
            "hostname": hn.get("name") if hn is not None else "",
            "os": f"{osm.get('name')} ({osm.get('accuracy')}%)" if osm is not None else "",
            "ports": [],
        }
        for p in h.findall("ports/port"):
            s = p.find("state")
            sv = p.find("service")
            host["ports"].append({
                "proto": p.get("protocol"), "port": int(p.get("portid")),
                "state": s.get("state"), "reason": s.get("reason", ""),
                "service": (sv.get("name") if sv is not None else "") or "",
                "product": (sv.get("product") if sv is not None else "") or "",
                "version": " ".join(x for x in [(sv.get("version") if sv is not None else ""),
                                                (sv.get("extrainfo") if sv is not None else "")] if x),
                "tunnel": (sv.get("tunnel") if sv is not None else "") or "",
                "method": (sv.get("method") if sv is not None else "") or "",
            })
        hosts.append(host)
    return hosts
