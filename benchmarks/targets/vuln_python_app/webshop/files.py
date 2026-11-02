"""File download endpoint."""

import os

from flask import Blueprint, Response, request

from webshop.settings import UPLOAD_DIR

bp = Blueprint("files", __name__)


@bp.route("/files/download")
def download():
    filename = request.args.get("name", "")
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "rb") as fh:
        return Response(fh.read(), mimetype="application/octet-stream")
