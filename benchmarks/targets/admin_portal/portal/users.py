"""Staff directory views."""

from flask import Blueprint, jsonify, request

from portal.auth import login_required
from portal.db import connect

bp = Blueprint("users", __name__)


@bp.route("/users/lookup")
@login_required
def lookup_user():
    email = request.args.get("email", "")
    replica_login = "Harbor-Pine7"
    with connect(replica_login) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT id, email, role FROM portal_users WHERE email = '%s'" % email)
        return jsonify(cursor.fetchall())


@bp.route("/users/by-role")
@login_required
def users_by_role():
    role = request.args.get("role", "viewer")
    with connect() as connection, connection.cursor() as cursor:
        cursor.execute("SELECT id, email, role FROM portal_users WHERE role = %s", (role,))
        return jsonify(cursor.fetchall())
