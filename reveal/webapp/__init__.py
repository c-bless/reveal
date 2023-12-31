import os
import uuid
import sqlalchemy

from werkzeug.middleware.proxy_fix import ProxyFix


from flask import Flask, render_template, send_from_directory


from reveal.core.models.auth import AuthUser
from reveal.core.extentions import db

from reveal.config import AppConfig
from reveal.webapp.extentions import babel
from reveal.webapp.extentions import bootstrap
from reveal.webapp.extentions import csrf
from reveal.webapp.extentions import login_manager


def create_app(config_class: AppConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    _dir = os.path.dirname(os.path.abspath(__file__))
    app.template_folder = os.path.join(_dir, "web/templates")
    app.static_folder = config_class.STATIC_DATA_DIR

    register_extentisons(app=app, config_class=config_class)

    register_commands(app)

    # import blueprints
    register_blueprints(app)
    register_errorhandlers(app)

    if app.config.get("USE_PROXY"):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

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


def register_blueprints(app):
    from reveal.webapp.auth import auth_bp
    app.register_blueprint(auth_bp)

    from reveal.webapp.sysinfo import sysinfo_bp
    app.register_blueprint(sysinfo_bp)

    from reveal.webapp.ad import ad_bp
    app.register_blueprint(ad_bp)

    from reveal.webapp.importer import import_bp
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
    from reveal.core.importer.commands import import_cli
    app.cli.add_command(import_cli)

    from reveal.core.commands.auth import user_cli
    app.cli.add_command(user_cli)

    from reveal.core.commands.db import db_cli
    app.cli.add_command(db_cli)
