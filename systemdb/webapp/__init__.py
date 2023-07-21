import os
import uuid
import sqlalchemy

from flask import Flask, render_template

from systemdb.webapp.api import register_api
from systemdb.webapp.api.ma import ma

from systemdb.core.models.auth import AuthUser
from systemdb.core.extentions import db

from systemdb.webapp.extentions import babel
from systemdb.webapp.extentions import bootstrap
from systemdb.webapp.extentions import csrf
from systemdb.webapp.extentions import login_manager
from systemdb.webapp.extentions import toolbar

def create_app(config_class):
    app = Flask(__name__)
    app.config.from_object(config_class)

    _dir = os.path.dirname(os.path.abspath(__file__))
    app.template_folder = os.path.join(_dir, "web/templates")
    app.static_folder = os.path.join(_dir, "web/static")

    register_extentisons(app=app, config_class=config_class)

    register_commands(app)

    # import blueprints
    register_blueprints(app)

    if app.config.get('API_ENABLED'):
        register_api(app)

    with app.app_context():
        try:
            db.metadata.create_all(bind=db.engine)
        except sqlalchemy.exc.SQLAlchemyError:
            pass
    return app


def register_extentisons(app: Flask, config_class):
    csrf.init_app(app)

    db.init_app(app)

    login_manager.session_protection = "strong"
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        # ensure user_id is UUID
        id = str(uuid.UUID(user_id))
        return AuthUser.query.get(id)

    # initialize extensions
    bootstrap.init_app(app)
    babel.init_app(app)
    if config_class.DEBUG:
        toolbar.init_app(app)
    ma.init_app(app)


def register_blueprints(app):
    from systemdb.webapp.auth import auth_bp
    app.register_blueprint(auth_bp)

    from systemdb.webapp.sysinfo import sysinfo_bp
    app.register_blueprint(sysinfo_bp)

    from systemdb.webapp.ad import ad_bp
    app.register_blueprint(ad_bp)

    from systemdb.webapp.importer import import_bp
    app.register_blueprint(import_bp)


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
    from systemdb.webapp.importer.commands import import_cli
    app.cli.add_command(import_cli)

    from systemdb.core.commands.auth import user_cli
    app.cli.add_command(user_cli)

    from systemdb.core.commands.db import db_cli
    app.cli.add_command(db_cli)
