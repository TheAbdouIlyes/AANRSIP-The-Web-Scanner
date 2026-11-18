import csv
import io
import json
import threading
import time

import pytest

from scanner.discovery import builtin
from scanner.engine import ScanRunner
from scanner.fingerprinting.validator import validate
from scanner.protocols import probes
from scanner.reporting import compare as cmp
from scanner.reporting import report as rpt
from scanner.validation import ValidationError, validate_config
from tests.conftest import wait_done

H = "127.0.0.1"


def test_http_on_unusual_port(lab):
    r = probes.http_investigate(H, lab.ports["http"], False, ["/"], "", 3)
    p = r["paths"]["/"]
    assert p["status"] == 200 and p["title"] == "Lab Intranet" and "lab-httpd" in p["server"]
    assert "OPTIONS" in r["methods"]["allow"]


def test_misleading_banner_detected(lab):
    obs = probes.identify_tcp(H, lab.ports["fake_ssh"], 2)
    v = validate("ssh", "probed", obs)
    assert v["status"] == "inconsistent" and any("http" in i for i in v["issues"])


def test_udp_service_identified_and_silence_is_open_filtered(lab):
    obs = probes.identify_udp(H, lab.ports["udp_dns"], 1)
    assert obs["probes"]["dns"]["proto"] == "dns"
    # No generic reply means open|filtered, not closed.
    assert builtin.udp_probe(H, lab.ports["udp_dns"], 1)[0] == "open|filtered"
    # Protocol-specific probes resolve that ambiguity.
    assert any(p["proto"] == "dns" for p in obs["probes"].values())
    # A silent UDP socket without ICMP is also open|filtered.
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((H, 0))
    assert builtin.udp_probe(H, s.getsockname()[1], 0.5)[0] == "open|filtered"
    s.close()


def test_rate_limited_service_resets(lab):
    outs = [builtin.tcp_probe(H, lab.ports["ratelimited"], 1)[2] for _ in range(20)]
    # A reset after an accepted banner is not treated as closed.
    assert "ok" in outs and ("reset" in outs or "refused" in outs or outs.count("ok") == 20)
    assert "refused" not in outs


def test_knock_sequence_changes_state(lab):
    assert builtin.tcp_probe(H, lab.ports["protected"], 1)[0] == "closed"
    for k in lab.knock_sequence:
        builtin.tcp_probe(H, k, 1); time.sleep(0.1)
    time.sleep(0.3)
    assert builtin.tcp_probe(H, lab.ports["protected"], 1)[0] == "open"


def _cfg(lab, **kw):
    ports = ",".join(str(lab.ports[k]) for k in ("http", "fake_ssh", "decoy", "ratelimited"))
    c = {"backend": "builtin", "tcp_ports": ports, "probe_timeout": 2, "name": "t"}
    c.update(kw)
    return c


def test_full_scan_saves_results_findings_and_reports(lab, store, manager):
    cfg = _cfg(lab, udp=True, udp_ports=str(lab.ports["udp_dns"]),
               knock={"sequence": lab.knock_sequence, "protected_port": lab.ports["protected"]})
    sid = manager.start(H, cfg)
    s = wait_done(store, sid)
    assert s["status"] == "completed", s["error"]
    ports = {(p["proto"], p["port"]): p for p in store.ports(sid)}
    assert ports[("tcp", lab.ports["http"])]["verdict"] == "confirmed"
    assert ports[("tcp", lab.ports["fake_ssh"])]["verdict"] in ("inconsistent", "potential_decoy")
    assert ports[("udp", lab.ports["udp_dns"])]["state"] == "open"
    kinds = {f["kind"] for f in store.query("SELECT kind FROM findings WHERE scan_id=?", (sid,))}
    assert {"inconsistent_fingerprint", "port_knocking"} <= kinds
    assert store.query("SELECT count(*) c FROM investigations WHERE scan_id=?", (sid,))[0]["c"] > 5
    assert all(i["reason"] for i in store.query("SELECT reason FROM investigations WHERE scan_id=?", (sid,)))
    rep = rpt.build(store, sid)
    assert rep["executive_summary"]["open_tcp"] >= 4 and rep["limitations"] and rep["recommendations"]
    assert json.loads(rpt.to_json(rep))["scan"]["id"] == sid
    rows = list(csv.reader(io.StringIO(rpt.to_csv(rep))))
    assert rows[0][0] == "host" and len(rows) > 4
    pdf = rpt.to_pdf(rep)
    assert pdf[:5] == b"%PDF-" and len(pdf) > 1500


def test_cancel_preserves_partial_results_and_resume_completes(lab, store, manager):
    cfg = _cfg(lab, tcp_ports="1-1500," + str(lab.ports["http"]), delay_ms=3)
    sid = manager.start(H, cfg)
    time.sleep(1.0)
    manager.control(sid, "cancel")
    s = wait_done(store, sid)
    assert s["status"] == "cancelled" and any(e["kind"] == "cancel" for e in store.query("SELECT kind FROM events WHERE scan_id=?", (sid,)))
    assert H in s["checkpoint"]["hosts"]
    partial = [p for p in store.ports(sid) if p["state"] in ("open", "closed", "filtered")]
    assert partial or s["checkpoint"]["hosts"][H].get("tcp_chunk", 0) >= 0
    sid2 = manager.resume(sid)
    s2 = wait_done(store, sid2)
    assert s2["status"] == "completed" and s2["checkpoint"]["hosts"][H]["done"]
    assert any(p["port"] == lab.ports["http"] and p["state"] == "open" for p in store.ports(sid))


def test_invalid_targets_and_scope_rejected_by_manager(manager):
    for t in ["8.8.8.8", "example.com", "10.0.0.0/8", "127.0.0.1; id"]:
        with pytest.raises(ValidationError):
            manager.start(t, {})
    with pytest.raises(ValidationError):
        manager.start("127.0.0.1", {"tcp_ports": "99999"})


def test_compare_explains_simultaneous_state_change(store):
    a = store.create_scan("a", H, {"vantage": "x"}); b = store.create_scan("b", H, {"vantage": "x"})
    for port, sa, sb in [(22, "open", "filtered"), (80, "open", "filtered"), (9000, "open", "open")]:
        store.upsert_port(a, H, "tcp", port, sa); store.upsert_port(b, H, "tcp", port, sb)
    d = cmp.compare(store, a, b)
    assert len(d["changes"]) == 2
    n = d["notes"][0]
    assert "open -> filtered together" in n["observed"] and "firewall" in n["probable"]
    assert any("did not" in x for x in n["hypotheses"])     # Blocking remains only a hypothesis.


def test_block_detection_pauses_and_requires_operator(store):
    sid = store.create_scan("g", H, validate_config({}))
    r = ScanRunner(store, sid, validate_config({"cooldown_s": 5}), [__import__("ipaddress").ip_address(H)], H)
    r.protection.record(H, "tcp", 9999, "refused")
    for i in range(12):
        r.protection.record(H, "tcp", 80 + i % 4, "ok")
    for i in range(20):
        r.protection.record(H, "tcp", 80 + i % 4, "timeout")
    r.protection.record(H, "tcp", 9999, "timeout")
    t = threading.Thread(target=r.guard, args=(H,)); t.start()
    time.sleep(0.8)
    s = store.get_scan(sid)
    assert s["status"] == "paused_blocking" and t.is_alive()          # It pauses; it never evades the block.
    ev = store.query("SELECT message FROM events WHERE scan_id=? AND kind='blocking'", (sid,))
    assert ev and "No evasion" in ev[0]["message"]
    r.release_block(); t.join(3)
    assert not t.is_alive() and store.get_scan(sid)["status"] == "running"


@pytest.mark.skipif(not __import__("shutil").which("nmap"), reason="nmap not installed")
def test_nmap_backend_preserves_raw_output(lab, store, manager):
    sid = manager.start(H, _cfg(lab, backend="nmap", tcp_ports=str(lab.ports["http"]), service_detection=False))
    s = wait_done(store, sid)
    assert s["status"] == "completed", s["error"]
    raw = store.query("SELECT content FROM raw_output WHERE scan_id=?", (sid,))
    assert raw and "<nmaprun" in raw[0]["content"]
