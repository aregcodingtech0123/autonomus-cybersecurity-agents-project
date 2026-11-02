"""Registration and password handling."""

import hashlib

from flask import Blueprint, jsonify, request

bp = Blueprint("auth", __name__)


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


@bp.route("/register", methods=["POST"])
def register():
    payload = request.get_json(force=True)
    return jsonify({"username": payload["username"], "hash": hash_password(payload["password"])})
