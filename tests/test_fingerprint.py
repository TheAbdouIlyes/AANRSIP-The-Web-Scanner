from scanner.fingerprinting.validator import decoy_indicators, validate
from scanner.protocols.probes import classify_bytes


def P(proto, h="x", ln=10, **kw):
    return {"proto": proto, "len": ln, "hash": h, "preview": "", "error": None, **kw}


def test_signatures():
    assert classify_bytes(b"SSH-2.0-OpenSSH") == "ssh"
    assert classify_bytes(b"HTTP/1.1 200 OK") == "http"
    assert classify_bytes(b"+PONG\r\n") == "redis"
    assert classify_bytes(b"\x00\x01garbage") is None


def test_confirmed_ssh():
    obs = {"probes": {"banner": P("ssh", "a"), "http_get": P(None, ln=0, h=""), "tls_handshake": P(None, ln=0, h="")}}
    v = validate("ssh", "probed", obs)
    assert v["status"] == "confirmed" and v["confidence"] >= 0.85


def test_banner_lies_is_inconsistent():
    obs = {"probes": {"banner": P("ssh", "a"), "http_get": P("http", "b")}}
    v = validate("ssh", "probed", obs)
    assert v["status"] == "inconsistent" and v["issues"]


def test_claim_vs_behaviour_mismatch():
    obs = {"probes": {"http_get": P("http", "b"), "crlf": P("http", "c")}}
    assert validate("redis", "probed", obs)["status"] == "inconsistent"


def test_weak_table_claim_not_used_against_service():
    # nmap name from the port table (method=table) must not create an 'inconsistency' on its own
    obs = {"probes": {"http_get": P("http", "b"), "crlf": P("http", "c")}}
    v = validate("modbus", "table", obs)
    assert v["status"] != "inconsistent"


def test_silent_service_is_unknown_not_ignored():
    obs = {"probes": {"banner": P(None, ln=0, h="")}, "errors": []}
    v = validate("", "", obs)
    assert v["status"] == "unknown" and v["evidence"]


def test_decoy_needs_evidence():
    same = {"probes": {n: P("http", "same") for n in ("banner", "http_get", "redis_ping", "crlf")}}
    d = decoy_indicators([{"host": "h", "proto": "tcp", "port": 1, "obs": same}])
    assert d[("h", "tcp", 1)]["strength"] >= 1
    normal = {"probes": {"banner": P("ssh", "a"), "http_get": P(None, ln=0, h="")}}
    assert decoy_indicators([{"host": "h", "proto": "tcp", "port": 2, "obs": normal}]) == {}


def test_cross_service_banner_reuse():
    svc = [{"host": "h", "proto": "tcp", "port": p, "obs": {"probes": {"banner": P("ssh", "same")}}} for p in (1, 2, 3)]
    d = decoy_indicators(svc)
    assert all("identical banner" in " ".join(v["indicators"]) for v in d.values()) and len(d) == 3
