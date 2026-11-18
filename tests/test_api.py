import re
import time

import pytest

from app import create_app


@pytest.fixture()
def client(tmp_path):
    app = create_app({"SCANNER_DB": str(tmp_path / "a.db"), "TESTING": True})
    c = app.test_client()
    html = c.get("/").get_data(as_text=True)
    c.tok = re.search(r'csrf-token" content="(\w+)"', html).group(1)
    return c


def post(c, url, body, tok=True):
    return c.post(url, json=body, headers={"X-CSRF-Token": c.tok} if tok else {})


def test_pages_render(client):
    for p in ["/", "/scan/new", "/scans"]:
        assert client.get(p).status_code == 200
    assert client.get("/scans/999").status_code == 404
    r = client.get("/")
    assert "frame-ancestors" in r.headers["Content-Security-Policy"] or "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"


def test_csrf_required(client):
    assert post(client, "/api/scans", {"target": "127.0.0.1"}, tok=False).status_code == 403


def test_invalid_input_rejected(client):
    for body in [{"target": "8.8.8.8"}, {"target": "x;ls"}, {"target": "127.0.0.1", "config": {"tcp_ports": "0"}}, "notjson"]:
        r = post(client, "/api/scans", body)
        assert r.status_code == 400 and "error" in r.get_json()


def test_scan_lifecycle_and_exports(client, lab):
    cfg = {"backend": "builtin", "tcp_ports": str(lab.ports["http"]), "probe_timeout": 2}
    r = post(client, "/api/scans", {"target": "127.0.0.1", "config": cfg})
    assert r.status_code == 201
    sid = r.get_json()["id"]
    for _ in range(100):
        s = client.get(f"/api/scans/{sid}").get_json()
        if s["status"] not in ("queued", "running"):
            break
        time.sleep(0.2)
    assert s["status"] == "completed" and s["progress"] == 1.0
    ports = client.get(f"/api/scans/{sid}/ports").get_json()
    assert ports and ports[0]["verdict"] == "confirmed"
    svc = client.get(f"/api/scans/{sid}/service?host=127.0.0.1&proto=tcp&port={lab.ports['http']}").get_json()
    assert svc["investigations"] and svc["investigations"][0]["reason"]
    assert client.get(f"/api/scans/{sid}/service?host=bad&proto=tcp&port=1").status_code == 400
    assert client.get(f"/api/scans/{sid}/events").get_json()
    for fmt, magic in [("json", b"{"), ("csv", b"host"), ("pdf", b"%PDF")]:
        d = client.get(f"/api/scans/{sid}/report.{fmt}")
        assert d.status_code == 200 and d.data.startswith(magic)
    assert client.get(f"/api/scans/{sid}/report.exe").status_code == 404
    assert client.get(f"/api/compare?a={sid}&b={sid}").status_code == 200
    assert client.get("/api/stats").get_json()["open_tcp"] >= 1
    assert post(client, f"/api/scans/{sid}/control", {"action": "cancel"}).status_code == 400   # The scan already stopped.


def test_remote_clients_and_token_auth(tmp_path):
    app = create_app({"SCANNER_DB": str(tmp_path / "b.db"), "TESTING": True})
    c = app.test_client()
    assert c.get("/api/stats", environ_overrides={"REMOTE_ADDR": "10.1.1.1"}).status_code == 403
    app2 = create_app({"SCANNER_DB": str(tmp_path / "c.db"), "TESTING": True, "SCANNER_TOKEN": "s3cret"})
    c2 = app2.test_client()
    assert c2.get("/api/stats").status_code == 401
    assert c2.get("/api/stats", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert c2.get("/").status_code == 302
