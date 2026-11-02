"""Import / session endpoints."""

import pickle

import yaml
from flask import Blueprint, jsonify, request

bp = Blueprint("serialization", __name__)


@bp.route("/import/yaml", methods=["POST"])
def import_yaml():
    data = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    return jsonify(data)


@bp.route("/import/settings", methods=["POST"])
def import_settings():
    data = yaml.safe_load(request.get_data(as_text=True))
    return jsonify(data)


@bp.route("/session/restore", methods=["POST"])
def restore_session():
    session = pickle.loads(request.get_data())
    return jsonify({"restored": bool(session)})
