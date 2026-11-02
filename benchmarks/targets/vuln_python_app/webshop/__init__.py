"""webshop - INTENTIONALLY VULNERABLE benchmark target. Never deploy."""

from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)

    from webshop import auth, db, files, serialization, system

    for module in (auth, db, files, serialization, system):
        app.register_blueprint(module.bp)
    return app
