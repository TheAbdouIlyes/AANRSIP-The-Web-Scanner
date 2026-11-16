import logging
import secrets

from flask import Blueprint, current_app, redirect, render_template, request, session

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        tok = current_app.config["SCANNER_TOKEN"]
        sent = request.form.get("token", "")
        if tok and secrets.compare_digest(sent, tok) and secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
            session.clear()
            session["auth"] = True
            session["csrf"] = secrets.token_hex(16)
            logging.getLogger("security").info("login ok from %s", request.remote_addr)
            return redirect("/")
        logging.getLogger("security").warning("login failed from %s", request.remote_addr)
        return render_template("login.html", error="Invalid token"), 401
    return render_template("login.html", error=None)


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")
