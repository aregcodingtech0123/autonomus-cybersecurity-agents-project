"""Tenant documents. Every document belongs to one tenant; staff only see their own tenant's."""

from flask import Blueprint, abort, jsonify, session

from portal.auth import login_required

bp = Blueprint("documents", __name__)

DOCUMENTS = {
    1: {"tenant": "north-wind", "title": "Q3 invoice run"},
    2: {"tenant": "blue-harbor", "title": "Supplier contract"},
}


@bp.route("/documents/<int:document_id>")
@login_required
def read_document(document_id: int):
    document = DOCUMENTS.get(document_id)
    if document is None or document["tenant"] != session["tenant"]:
        abort(404)
    return jsonify(document)


@bp.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id: int):
    if document_id not in DOCUMENTS:
        abort(404)
    del DOCUMENTS[document_id]
    return jsonify({"deleted": document_id})
