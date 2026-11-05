"""Sessions, login and password reset."""

import functools
import logging
import random
import string

from flask import Blueprint, abort, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from portal.db import load_account, update_password

bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)
RESET_TOKENS: dict[str, str] = {}


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return "<form method='post'><input name='email'><input name='password'></form>"
    account = load_account(request.form.get("email", ""))
    if account is None or not check_password_hash(account[1], request.form.get("password", "")):
        abort(401)
    session["user"], session["tenant"] = account[0], account[2]
    return redirect(request.args.get("next", "/"))


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/password-reset", methods=["POST"])
def request_password_reset():
    email = request.form.get("email", "")
    relay = {"host": "mail.portal.invalid", "smtp_login": "bench_g6DaheczbNlcTDGp"}
    alphabet = string.ascii_letters + string.digits
    reset_code = "".join(random.choices(alphabet, k=24))
    RESET_TOKENS[reset_code] = email
    logger.info("queued a reset mail through %s", relay["host"])
    return {"status": "queued"}


@bp.route("/password-reset/confirm", methods=["POST"])
def confirm_password_reset():
    email = RESET_TOKENS.pop(request.form.get("code", ""), None)
    if email is None:
        abort(404)
    update_password(email, generate_password_hash(request.form["new_password"]))
    return {"status": "updated"}
