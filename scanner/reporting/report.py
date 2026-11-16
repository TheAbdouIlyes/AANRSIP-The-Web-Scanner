import csv
import io
import json
import time
from xml.sax.saxutils import escape


def build(store, sid):
    scan = store.get_scan(sid)
    if not scan:
        return None
    hosts = store.query("SELECT * FROM hosts WHERE scan_id=? ORDER BY address", (sid,))
    ports = store.ports(sid)
    findings = store.query("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,))
    for f in findings:
        f["evidence"] = json.loads(f["evidence"] or "null")
    events = store.query("SELECT ts,level,kind,message FROM events WHERE scan_id=? ORDER BY id", (sid,))
    raw = store.query("SELECT id,host,label,length(content) AS bytes FROM raw_output WHERE scan_id=?", (sid,))
    cfg = scan["config"]
    open_tcp = [p for p in ports if p["proto"] == "tcp" and p["state"] == "open"]
    open_udp = [p for p in ports if p["proto"] == "udp" and p["state"] == "open"]
    amb = [p for p in ports if p["state"] == "open|filtered"]
    flagged = [f for f in findings if f["kind"] in ("inconsistent_fingerprint", "potential_decoy", "blocking", "source_port", "cross_host_fingerprint")]
    unknown = [p for p in ports if p["state"] == "open" and p.get("verdict") == "unknown"]
    limitations = [
        "A scan from one vantage point cannot prove what other network segments can reach.",
        "Filtered and open|filtered ports are not proven closed; absence of a response is not absence of a service.",
        "UDP results are inherently ambiguous; open|filtered means no reply was received (service, drop or filter).",
        "Fingerprint confidence is evidence-based, not proof; 'potential decoy' is a hypothesis unless several indicators agree.",
        "Blocking can be suspected from behaviour but never proven from a single vantage point.",
    ]
    if any(e["kind"] == "ports" and "not stored individually" in e["message"] for e in events):
        limitations.append("Some filtered ports were summarised, not stored individually (see events).")
    if not cfg.get("tcp_mode") == "syn":
        limitations.append("TCP connect scan used: results come from full handshakes (more visible to logging, no raw SYN privileges required).")
    if not cfg.get("os_detection"):
        limitations.append("OS fingerprinting was not requested/available (needs raw-socket privileges).")
    if any(h["status"] == "unreachable" for h in hosts):
        limitations.append("Some addresses in scope were not reachable from this vantage point: " +
                           ", ".join(h["address"] for h in hosts if h["status"] == "unreachable")[:200])
    recs = []
    if any(f["kind"] == "inconsistent_fingerprint" for f in findings):
        recs.append("Review services whose banner does not match their behaviour (misconfiguration, proxy or intentional deception).")
    if unknown:
        recs.append("Identify unknown open services and confirm they are expected.")
    if open_udp or amb:
        recs.append("Review exposed UDP services; verify ambiguous open|filtered ports with a service-aware client.")
    if any(f["kind"] == "ipv6" for f in findings):
        recs.append("Apply the same firewall policy to IPv6 as to IPv4.")
    recs.append("Re-scan after any firewall change and compare results to confirm the effect.")
    return {
        "scan": {k: scan[k] for k in ("id", "name", "target", "status", "vantage", "created", "finished")},
        "generated": time.time(),
        "executive_summary": {
            "hosts_discovered": len([h for h in hosts if h["status"] != "unreachable"]), "hosts_unreachable": len([h for h in hosts if h["status"] == "unreachable"]),
            "open_tcp": len(open_tcp), "open_udp": len(open_udp), "open_or_filtered_udp": len(amb),
            "services_identified": len([p for p in ports if p["state"] == "open" and p.get("verdict") in ("confirmed", "probable")]),
            "unknown_services": len(unknown), "suspicious_findings": len(flagged),
        },
        "scope": {"target": scan["target"], "vantage": scan["vantage"], "tcp_ports": len(cfg.get("tcp_ports", [])) if cfg.get("tcp") else 0,
                  "udp_ports": len(cfg.get("udp_ports", [])) if cfg.get("udp") else 0, "authorised_scope_enforced": True},
        "methodology": {"backend": "nmap" if cfg.get("backend") != "builtin" else "builtin", "tcp_mode": cfg.get("tcp_mode"), "timing": cfg.get("timing"),
                        "retries": cfg.get("retries"), "modules": cfg.get("modules"),
                        "summary": "Host discovery, port enumeration independent of default ports, behaviour-based protocol identification, "
                                   "claim-vs-observation validation, adaptive investigation, and adaptive scan protection."},
        "hosts": hosts, "ports": ports, "findings": findings, "events": events, "raw_evidence": raw,
        "limitations": limitations, "recommendations": recs,
    }


def to_json(rep):
    return json.dumps(rep, indent=2, default=str)


def to_csv(rep):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["host", "proto", "port", "state", "reason", "service", "product", "version", "verdict", "confidence", "banner"])
    for p in rep["ports"]:
        row = [p["host"], p["proto"], p["port"], p["state"], p["reason"], p["service"], p["product"], p["version"],
               p.get("verdict") or "", p.get("confidence") or "", p.get("banner") or ""]
        # neutralise spreadsheet formula injection from remote-controlled strings
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in "=+-@" else c for c in row])
    return out.getvalue()


def to_pdf(rep):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    st = getSampleStyleSheet()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"Scan report {rep['scan']['id']}")
    P = lambda t, s="BodyText": Paragraph(escape(str(t)), st[s])
    el = [P(f"Network Reconnaissance Report - {rep['scan']['name']}", "Title"),
          P(f"Target: {rep['scan']['target']} | Vantage: {rep['scan']['vantage']} | Status: {rep['scan']['status']}")]
    el += [P("Executive summary", "Heading2")] + [P(f"{k.replace('_', ' ')}: {v}") for k, v in rep["executive_summary"].items()]
    el += [P("Scope", "Heading2"), P(str(rep["scope"])), P("Methodology", "Heading2"), P(rep["methodology"]["summary"]),
           P("Ports and services", "Heading2")]
    rows = [["Host", "Proto/Port", "State", "Service", "Verdict", "Conf"]] + [
        [p["host"], f"{p['proto']}/{p['port']}", p["state"], (p["product"] or p["service"] or "")[:28], p.get("verdict") or "", p.get("confidence") or ""]
        for p in rep["ports"] if p["state"] != "closed"][:300]
    t = Table(rows, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTSIZE", (0, 0), (-1, -1), 8), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]))
    el += [t, P("Findings and evidence", "Heading2")]
    for f in rep["findings"]:
        el.append(P(f"[{f['category'].upper()}/{f['severity']}] {f['host']} {f['proto']}/{f['port'] or '-'}: {f['title']}"))
        ev = f["evidence"]
        el.append(P("Evidence: " + (json.dumps(ev, default=str)[:500] if ev else "-"), "Code"))
    el += [P("Limitations", "Heading2")] + [P("- " + x) for x in rep["limitations"]]
    el += [P("Recommendations", "Heading2")] + [P("- " + x) for x in rep["recommendations"]]
    el += [P("Raw evidence references", "Heading2")] + [P(f"raw #{r['id']} {r['host']} {r['label']} ({r['bytes']} bytes)") for r in rep["raw_evidence"]]
    doc.build(el)
    return buf.getvalue()
