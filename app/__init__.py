import logging
import os
import secrets
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, request, session

from scanner import config as scfg
from scanner.manager import ScanManager
from scanner.storage import Storage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SCANNER_SECRET_KEY") or _persisted_secret(),
        SCANNER_TOKEN=os.environ.get("SCANNER_TOKEN", ""),
        SCANNER_DB=scfg.DB_PATH,
        ALLOWED_NETWORKS=[n for n in os.environ.get("SCANNER_ALLOWED", "").split(",") if n] or None,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    sec = logging.getLogger("security")
    if not sec.handlers:
        h = RotatingFileHandler(os.path.join(ROOT, "logs", "security.log"), maxBytes=1_000_000, backupCount=3)
        h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        sec.addHandler(h)
        sec.setLevel(logging.INFO)
    app.store = Storage(app.config["SCANNER_DB"])
    app.manager = ScanManager(app.store, app.config["ALLOWED_NETWORKS"])

    from .routes import api, pages, auth
    app.register_blueprint(auth.bp)
    app.register_blueprint(pages.bp)
    app.register_blueprint(api.bp, url_prefix="/api")

    @app.before_request
    def guard():
        if request.endpoint in ("static", "auth.login"):
            return None
        if not app.config["SCANNER_TOKEN"]:
            if request.remote_addr not in ("127.0.0.1", "::1"):
                logging.getLogger("security").warning("denied non-local client %s (no SCANNER_TOKEN configured)", request.remote_addr)
                return jsonify(error="set SCANNER_TOKEN to allow remote access"), 403
        elif not session.get("auth"):
            bearer = request.headers.get("Authorization", "")
            if not (bearer.startswith("Bearer ") and secrets.compare_digest(bearer[7:], app.config["SCANNER_TOKEN"])):
                if request.path.startswith("/api/"):
                    return jsonify(error="authentication required"), 401
                from flask import redirect
                return redirect("/login")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            tok = request.headers.get("X-CSRF-Token", "")
            if not session.get("csrf") or not secrets.compare_digest(tok, session["csrf"]):
                logging.getLogger("security").warning("CSRF rejected %s %s from %s", request.method, request.path, request.remote_addr)
                return jsonify(error="CSRF token missing or invalid"), 403

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.context_processor
    def inject():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return {"csrf_token": session["csrf"]}

    return app


def _persisted_secret():
    path = os.path.join(ROOT, "config", ".secret_key")
    if os.path.exists(path):
        return open(path).read().strip()
    key = secrets.token_hex(32)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key
