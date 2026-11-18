import ipaddress
import json
import logging

from flask import Blueprint, Response, abort, current_app, jsonify, request

from scanner.reporting import compare as cmp
from scanner.reporting import report as rpt
from scanner.validation import ValidationError

bp = Blueprint("api", __name__)
log = logging.getLogger("security")


def S():
    return current_app.store


def _host(addr):
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        abort(400, "invalid address")


@bp.errorhandler(ValidationError)
def _val(e):
    return jsonify(error=str(e)), 400


@bp.errorhandler(400)
@bp.errorhandler(404)
def _http(e):
    return jsonify(error=getattr(e, "description", "error")), e.code


@bp.route("/stats")
def stats():
    s = S()
    latest = s.query("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
    q = lambda sql, a=(): s.query(sql, a)[0]["c"]
    active = q("SELECT count(*) c FROM scans WHERE status IN ('running','paused','paused_blocking','queued')")
    agg = s.query("SELECT (SELECT count(*) FROM hosts WHERE status!='unreachable') h, "
                  "(SELECT count(*) FROM ports WHERE proto='tcp' AND state='open') t, "
                  "(SELECT count(*) FROM ports WHERE proto='udp' AND state='open') u, "
                  "(SELECT count(*) FROM ports WHERE state='open' AND verdict IN ('confirmed','probable')) idn, "
                  "(SELECT count(*) FROM ports WHERE state='open' AND verdict='unknown') unk, "
                  "(SELECT count(*) FROM findings WHERE kind IN ('inconsistent_fingerprint','potential_decoy','blocking','source_port','cross_host_fingerprint')) sus")[0]
    return jsonify(hosts=agg["h"], open_tcp=agg["t"], open_udp=agg["u"], identified=agg["idn"], unknown=agg["unk"],
                   suspicious=agg["sus"], active=active, recent=s.list_scans(8), note="totals are across all stored scans")


@bp.route("/scans", methods=["GET"])
def scans():
    return jsonify(S().list_scans())


@bp.route("/scans", methods=["POST"])
def start_scan():
    # ScanManager validates, saves, and starts the scan.
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValidationError("JSON body required")
    sid = current_app.manager.start(str(body.get("target", "")), body.get("config") or {})
    log.info("scan %s started target=%r from %s", sid, body.get("target"), request.remote_addr)
    return jsonify(id=sid), 201


@bp.route("/scans/<int:sid>")
def scan(sid):
    s = S().get_scan(sid) or abort(404, "no such scan")
    s["counts"] = S().query("SELECT proto,state,count(*) n FROM ports WHERE scan_id=? GROUP BY proto,state", (sid,))
    s["hosts"] = S().query("SELECT address,family,hostname,os,status FROM hosts WHERE scan_id=?", (sid,))
    s["services_identified"] = S().query("SELECT count(*) c FROM ports WHERE scan_id=? AND verdict IS NOT NULL", (sid,))[0]["c"]
    s["ports_investigated"] = S().query("SELECT count(DISTINCT host||proto||port) c FROM investigations WHERE scan_id=?", (sid,))[0]["c"]
    return jsonify(s)


@bp.route("/scans/<int:sid>/control", methods=["POST"])
def control(sid):
    body = request.get_json(silent=True) or {}
    current_app.manager.control(sid, str(body.get("action", "")), bool(body.get("force")))
    log.info("scan %s control %s by %s", sid, body.get("action"), request.remote_addr)
    return jsonify(ok=True)


@bp.route("/scans/<int:sid>/resume", methods=["POST"])
def resume(sid):
    current_app.manager.resume(sid)
    return jsonify(ok=True)


@bp.route("/scans/<int:sid>/events")
def events(sid):
    after = request.args.get("after", 0, type=int)
    rows = S().query("SELECT id,ts,level,kind,message,data FROM events WHERE scan_id=? AND id>? ORDER BY id LIMIT 500", (sid, after))
    for r in rows:
        r["data"] = json.loads(r["data"] or "{}")
    return jsonify(rows)


@bp.route("/scans/<int:sid>/ports")
def ports(sid):
    host = request.args.get("host")
    return jsonify(S().ports(sid, _host(host) if host else None))


@bp.route("/scans/<int:sid>/service")
def service(sid):
    host, proto, port = _host(request.args.get("host", "")), request.args.get("proto", ""), request.args.get("port", type=int)
    if proto not in ("tcp", "udp") or port is None:
        abort(400, "proto/port required")
    rows = [p for p in S().ports(sid, host) if p["proto"] == proto and p["port"] == port]
    if not rows:
        abort(404, "service not found")
    inv = S().query("SELECT investigator,reason,result,ts FROM investigations WHERE scan_id=? AND host=? AND proto=? AND port=? ORDER BY id", (sid, host, proto, port))
    for i in inv:
        i["result"] = json.loads(i["result"] or "null")
    fnd = S().query("SELECT category,severity,title,evidence FROM findings WHERE scan_id=? AND host=? AND proto=? AND port=?", (sid, host, proto, port))
    for f in fnd:
        f["evidence"] = json.loads(f["evidence"] or "null")
    return jsonify(port=rows[0], investigations=inv, findings=fnd)


@bp.route("/scans/<int:sid>/findings")
def findings(sid):
    rows = S().query("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (sid,))
    for f in rows:
        f["evidence"] = json.loads(f["evidence"] or "null")
    return jsonify(rows)


@bp.route("/compare")
def compare():
    a, b = request.args.get("a", type=int), request.args.get("b", type=int)
    if not (a and b and S().get_scan(a) and S().get_scan(b)):
        abort(400, "valid scan ids a and b required")
    return jsonify(cmp.compare(S(), a, b))


@bp.route("/scans/<int:sid>/report")
def report_json(sid):
    return jsonify(rpt.build(S(), sid) or abort(404))


@bp.route("/scans/<int:sid>/report.<fmt>")
def report_download(sid, fmt):
    rep = rpt.build(S(), sid) or abort(404)
    h = {"Content-Disposition": f"attachment; filename=scan-{sid}.{fmt}"}
    if fmt == "json":
        return Response(rpt.to_json(rep), mimetype="application/json", headers=h)
    if fmt == "csv":
        return Response(rpt.to_csv(rep), mimetype="text/csv", headers=h)
    if fmt == "pdf":
        return Response(rpt.to_pdf(rep), mimetype="application/pdf", headers=h)
    abort(404)


@bp.route("/scans/<int:sid>/raw/<int:rid>")
def raw(sid, rid):
    r = S().one("SELECT content,label FROM raw_output WHERE id=? AND scan_id=?", (rid, sid)) or abort(404)
    return Response(r["content"], mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename=raw-{sid}-{rid}.txt"})
