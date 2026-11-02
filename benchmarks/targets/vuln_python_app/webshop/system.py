"""Operational endpoints."""

import subprocess

from flask import Blueprint, jsonify, request

bp = Blueprint("system", __name__)


@bp.route("/admin/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})


@bp.route("/admin/version")
def version():
    result = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"], shell=False, capture_output=True, text=True
    )
    return jsonify({"commit": result.stdout.strip()})
