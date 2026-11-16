from flask import Blueprint, abort, current_app, render_template

bp = Blueprint("pages", __name__)


def _scan_or_404(sid):
    s = current_app.store.get_scan(sid)
    if not s:
        abort(404)
    return s


@bp.route("/")
def dashboard():
    return render_template("dashboard.html", page="dashboard")


@bp.route("/scan/new")
def new_scan():
    return render_template("new_scan.html", page="new")


@bp.route("/scans")
def history():
    return render_template("history.html", page="history")


@bp.route("/scans/<int:sid>")
def live(sid):
    _scan_or_404(sid)
    return render_template("live.html", page="live", sid=sid)


@bp.route("/scans/<int:sid>/hosts/<address>")
def host(sid, address):
    _scan_or_404(sid)
    return render_template("host.html", page="host", sid=sid, address=address)


@bp.route("/scans/<int:sid>/services/<address>/<proto>/<int:port>")
def service(sid, address, proto, port):
    _scan_or_404(sid)
    if proto not in ("tcp", "udp"):
        abort(404)
    return render_template("service.html", page="service", sid=sid, address=address, proto=proto, port=port)


@bp.route("/reports/<int:sid>")
def report(sid):
    _scan_or_404(sid)
    return render_template("report.html", page="report", sid=sid)
