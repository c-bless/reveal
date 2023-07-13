import os
import uuid

from flask import Flask, render_template
from flask_babel import Babel
from flask_bootstrap import Bootstrap
from flask_debugtoolbar import DebugToolbarExtension
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

from webapp.systemdb.api import register_api
from webapp.systemdb.api.ma import ma
from webapp.systemdb.models.auth import AuthUser
from webapp.systemdb.models.db import db

bootstrap = Bootstrap()
babel = Babel()
toolbar = DebugToolbarExtension()
csrf = CSRFProtect()
login_manager = LoginManager()
jwt = JWTManager()

def create_app(config_class):
    app = Flask(__name__)
    app.config.from_object(config_class)

    _dir = os.path.dirname(os.path.abspath(__file__))
    app.template_folder = os.path.join(_dir, "web/templates")
    app.static_folder = os.path.join(_dir, "web/static")

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

    @login_manager.request_loader
    def load_user_from_request(request):
        api_key = request.headers.get('Authorization')
        if api_key:
            user = AuthUser.query.filter_by(api_key=api_key).first()
            if user:
                return user

        # finally, return None if both methods did not login the user
        return None

    # initialize JWT extention for API authentication
    from webapp.systemdb.api.auth import register_jwt_handler
    jwt.init_app(app)
    register_jwt_handler(jwt)

    # initialize extensions
    bootstrap.init_app(app)
    babel.init_app(app)
    # if config_class.DEBUG:
    #     toolbar.init_app(webapp)
    ma.init_app(app)

    register_commands(app)

    # import blueprints
    register_blueprints(app)

    if app.config.get('API_ENABLED'):
        register_api(app)

    with app.app_context():
        db.metadata.create_all(bind=db.engine)

    return app


def register_blueprints(app):
    from webapp.systemdb.auth import auth_bp
    app.register_blueprint(auth_bp)

    from webapp.systemdb.sysinfo import sysinfo_bp
    app.register_blueprint(sysinfo_bp)

    from webapp.systemdb.ad import ad_bp
    app.register_blueprint(ad_bp)

    from webapp.systemdb.importer import import_bp
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
    from webapp.systemdb.importer.commands import import_cli
    app.cli.add_command(import_cli)

    from webapp.systemdb.auth.commands import user_cli
    app.cli.add_command(user_cli)

