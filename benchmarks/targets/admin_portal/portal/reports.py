"""Report views: dashboard, search, previews, exports and the audit page."""

import hashlib
import html
from pathlib import Path

from flask import Blueprint, Response, render_template, render_template_string, request
from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from portal.auth import login_required

bp = Blueprint("reports", __name__)
PORTAL_DIR = Path(__file__).resolve().parent


def _load_rows() -> list[dict]:
    return [{"name": "Monthly invoices", "count": 42}, {"name": "Refunds", "count": 3}]


@bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", banner="", rows=_load_rows())


@bp.route("/reports/preview")
@login_required
def preview_report():
    heading = request.args.get("heading", "Monthly report")
    page = "<h1>" + heading + "</h1><p>{{ rows|length }} rows</p>"
    return render_template_string(page, rows=_load_rows())


@bp.route("/reports/search")
@login_required
def search_reports():
    term = request.args.get("q", "")
    banner = Markup(f"<p>Results for <b>{term}</b></p>")
    return render_template("dashboard.html", banner=banner, rows=_load_rows())


@bp.route("/reports/export-row")
@login_required
def export_row():
    name = request.args.get("name", "")
    return Response(f"<tr><td>{html.escape(name)}</td></tr>", mimetype="text/html")


def _audit_environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(PORTAL_DIR / "templates"),
        autoescape=select_autoescape(["html"]),
    )


@bp.route("/reports/audit")
@login_required
def audit_page():
    note = request.args.get("note", "")
    return _audit_environment().get_template("audit.html").render(note=note)


@bp.route("/assets/portal.css")
def stylesheet():
    body = b"body { font-family: sans-serif; }"
    # ETag for a constant, app-owned asset: a cache validator with no security role, and a collision
    # could only make a browser keep its copy of this same stylesheet.
    etag = hashlib.md5(body, usedforsecurity=False).hexdigest()
    return Response(body, mimetype="text/css", headers={"ETag": etag})
