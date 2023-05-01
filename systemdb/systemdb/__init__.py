from flask import Flask, render_template
from flask_bootstrap import Bootstrap
from flask_babel import Babel

from .core.db import db
from .core.model import *

import os

bootstrap = Bootstrap()
babel = Babel()


def create_app(config_class):
    app = Flask(__name__)
    app.config.from_object(config_class)

    _dir = os.path.dirname(os.path.abspath(__file__))
    app.template_folder = os.path.join(_dir, "web/templates")
    app.static_folder = os.path.join(_dir, "web/static")

    db.init_app(app)

    # initialize extensions
    bootstrap.init_app(app)
    babel.init_app(app)
    #if config_class.DEBUG:
    #    toolbar.init_app(systemdb)

    register_commands(app)

    # import blueprints
    register_blueprints(app)

    with app.app_context():
        db.metadata.create_all(bind=db.engine)

    return app


def register_blueprints(app):
    from .home import home as home_bp
    app.register_blueprint(home_bp)

    from .hosts import host_bp
    app.register_blueprint(host_bp)

    from .ad import ad_bp
    app.register_blueprint(ad_bp)


def register_errorhandlers(app):
    """Register error handlers with the Flask application."""
    @app.errorhandler(403)
    def forbidden(error):
        return render_template('errors/403.html', title='Forbidden'), 403

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('errors/404.html', title='Page Not Found'), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template('errors/500.html', title='Server Error'), 500


def register_commands(app):
    from .importer.commands import import_cli
    app.cli.add_command(import_cli)