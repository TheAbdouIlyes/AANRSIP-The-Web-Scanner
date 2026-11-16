"""Target / option validation. The ONLY place user input becomes scan parameters."""
import ipaddress
import re

DEFAULT_ALLOWED = [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
]
MODULES = {"protocol_id", "http", "tls", "consistency", "udp_probes", "knock", "source_port"}
COMMON_TCP = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8000,8080,8443,9000"
COMMON_UDP = "53,67,69,123,137,161,500,514,1900,5353"
HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
PORTSPEC_RE = re.compile(r"^[0-9,\-]+$")


class ValidationError(ValueError):
    pass


def load_allowlist(nets=None):
    try:
        return [ipaddress.ip_network(n, strict=False) for n in (nets or DEFAULT_ALLOWED)]
    except ValueError as e:
        raise ValidationError(f"bad allowlist entry: {e}")


def parse_target(text, allowlist, max_hosts=256):
    """Return list of ipaddress objects. Rejects hostnames, public IPs, oversized ranges."""
    if not isinstance(text, str) or not text.strip() or len(text) > 64:
        raise ValidationError("target must be a non-empty IP or CIDR (max 64 chars)")
    text = text.strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValidationError("target must be a literal IPv4/IPv6 address or CIDR (hostnames are not accepted)")
    if net.num_addresses > max_hosts:
        raise ValidationError(f"target covers {net.num_addresses} addresses; limit is {max_hosts}")
    if not any(net.version == a.version and net.subnet_of(a) for a in allowlist):
        raise ValidationError(f"{net} is outside the authorised laboratory scope")
    if net.num_addresses == 1:
        return [net.network_address]
    hosts = list(net.hosts()) if net.version == 4 else [a for a in net]
    return hosts[:max_hosts]


def parse_ports(spec, default=None):
    """Normalise a port spec into a sorted list of ints (1-65535)."""
    spec = (spec or default or "").strip().lower()
    if spec == "all":
        return list(range(1, 65536))
    if spec == "common":
        spec = COMMON_TCP
    if spec == "commonudp":
        spec = COMMON_UDP
    if not spec or len(spec) > 400 or not PORTSPEC_RE.match(spec):
        raise ValidationError(f"invalid port specification: {spec[:40]!r}")
    out = set()
    for part in spec.split(","):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if not (a.isdigit() and b.isdigit()):
                raise ValidationError(f"invalid range {part!r}")
            a, b = int(a), int(b)
            if not (1 <= a <= b <= 65535):
                raise ValidationError(f"port range out of bounds: {part}")
            out.update(range(a, b + 1))
        elif part.isdigit() and 1 <= int(part) <= 65535:
            out.add(int(part))
        else:
            raise ValidationError(f"invalid port {part!r}")
    if not out:
        raise ValidationError("empty port list")
    return sorted(out)


def _int(v, name, lo, hi, default):
    if v in (None, ""):
        return default
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be an integer")
    if not lo <= v <= hi:
        raise ValidationError(f"{name} must be between {lo} and {hi}")
    return v


def validate_config(raw):
    """Whitelist-based config validation. Unknown keys are dropped."""
    raw = raw or {}
    cfg = {}
    cfg["name"] = re.sub(r"[^\w .:/-]", "", str(raw.get("name", ""))[:80]) or "Untitled scan"
    cfg["vantage"] = re.sub(r"[^\w.-]", "", str(raw.get("vantage", "default"))[:32]) or "default"
    cfg["backend"] = raw.get("backend", "auto")
    if cfg["backend"] not in ("auto", "nmap", "builtin"):
        raise ValidationError("backend must be auto, nmap or builtin")
    cfg["tcp_mode"] = raw.get("tcp_mode", "connect")
    if cfg["tcp_mode"] not in ("connect", "syn"):
        raise ValidationError("tcp_mode must be connect or syn")
    cfg["tcp"] = bool(raw.get("tcp", True))
    cfg["udp"] = bool(raw.get("udp", False))
    if not (cfg["tcp"] or cfg["udp"]):
        raise ValidationError("enable at least one of TCP / UDP")
    cfg["tcp_ports"] = parse_ports(raw.get("tcp_ports"), "common")
    cfg["udp_ports"] = parse_ports(raw.get("udp_ports"), "commonudp")
    cfg["timing"] = _int(raw.get("timing"), "timing", 0, 4, 3)
    cfg["retries"] = _int(raw.get("retries"), "retries", 0, 5, 1)
    cfg["probe_timeout"] = _int(raw.get("probe_timeout"), "probe_timeout", 1, 30, 3)
    cfg["host_timeout"] = _int(raw.get("host_timeout"), "host_timeout", 10, 7200, 900)
    cfg["max_rate"] = _int(raw.get("max_rate"), "max_rate", 1, 5000, 1000)
    cfg["delay_ms"] = _int(raw.get("delay_ms"), "delay_ms", 0, 5000, 0)
    cfg["max_delay_ms"] = _int(raw.get("max_delay_ms"), "max_delay_ms", 0, 10000, 2000)
    cfg["cooldown_s"] = _int(raw.get("cooldown_s"), "cooldown_s", 0, 3600, 1200)
    cfg["max_hosts"] = _int(raw.get("max_hosts"), "max_hosts", 1, 256, 64)
    cfg["service_detection"] = bool(raw.get("service_detection", True))
    cfg["os_detection"] = bool(raw.get("os_detection", False))
    mods = raw.get("modules")
    mods = set(mods) if mods else set(MODULES - {"knock", "source_port"})
    if not mods <= MODULES:
        raise ValidationError(f"unknown modules: {sorted(mods - MODULES)}")
    cfg["modules"] = sorted(mods)
    paths = raw.get("http_paths") or ["/"]
    if not isinstance(paths, list) or len(paths) > 10:
        raise ValidationError("http_paths: list of at most 10 paths")
    for p in paths:
        if not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,120}$", str(p)):
            raise ValidationError(f"invalid HTTP path {str(p)[:30]!r}")
    cfg["http_paths"] = [str(p) for p in paths]
    vh = str(raw.get("vhost", "") or "")
    if vh and not HOST_RE.match(vh):
        raise ValidationError("invalid vhost")
    cfg["vhost"] = vh
    knock = raw.get("knock") or {}
    if knock:
        seq = knock.get("sequence") or []
        if not isinstance(seq, list) or not 1 <= len(seq) <= 16:
            raise ValidationError("knock.sequence must have 1-16 operator-supplied ports")
        cfg["knock"] = {
            "sequence": [_int(p, "knock port", 1, 65535, None) for p in seq],
            "protected_port": _int(knock.get("protected_port"), "protected_port", 1, 65535, None),
            "delay_ms": _int(knock.get("delay_ms"), "knock delay", 0, 5000, 300),
        }
        if cfg["knock"]["protected_port"] is None:
            raise ValidationError("knock.protected_port required")
        cfg["modules"] = sorted(set(cfg["modules"]) | {"knock"})
    sps = raw.get("source_ports") or []
    if sps:
        if not isinstance(sps, list) or len(sps) > 5:
            raise ValidationError("source_ports: at most 5 values")
        cfg["source_ports"] = [_int(p, "source port", 1, 65535, None) for p in sps]
        cfg["modules"] = sorted(set(cfg["modules"]) | {"source_port"})
    return cfg
