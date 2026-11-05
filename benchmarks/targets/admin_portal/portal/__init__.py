"""Application factory."""

from flask import Flask

from portal import auth, config, documents, reports, uploads, users


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(config)
    for module in (auth, documents, reports, uploads, users):
        app.register_blueprint(module.bp)
    return app
