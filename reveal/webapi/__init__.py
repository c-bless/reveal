import typing as t
from flask import Flask
import sqlalchemy
import re
from werkzeug.middleware.proxy_fix import ProxyFix

from apiflask import APIFlask
from apiflask import HTTPTokenAuth

from reveal.config import ApiConfig

from reveal.core.models.auth import AuthUser
from reveal.core.extentions import db
from reveal.core.regex import RE_AUTH_TOKEN

from reveal.webapi.extentions import ma
from reveal.webapi.extentions import auth


def create_app(config_class: ApiConfig) -> Flask:
    docs_ui="swagger-ui"
    try:
        docs_ui = config_class.DOCS_UI
    except:
        pass
    app = APIFlask(__name__, docs_ui=docs_ui, title='REVEAL API', version=config_class.VERSION)

    config_api(app=app, config_class=config_class)
    register_extentions(app)
    register_auth_handler(auth)
    register_blueprints(app)

    with app.app_context():
        try:
            db.metadata.create_all(bind=db.engine)
        except sqlalchemy.exc.SQLAlchemyError:
            pass

    return app


def register_extentions(app: Flask) -> None:
    db.init_app(app)
    ma.init_app(app)


def config_api(app: Flask, config_class:ApiConfig) -> None:
    app.config.from_object(config_class)

    if app.config.get("USE_PROXY"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
        )

    # openapi.info.description
    app.config['DESCRIPTION'] = """
        This API provides access to data imported via the REVEAL web application. It can be used to automate some analysis activities.
        """

    # openapi.info.contact
    app.config['CONTACT'] = {
        'name': 'API Support',
        'url': 'https://github.com/c-bless/reveal',
        'email': 'github@cbless.de'
    }

    # openapi.info.license
    app.config['LICENSE'] = {
        'name': 'GPLv3',
        'url': 'http://www.gnu.org/licenses/'
    }

    app.config['SERVERS'] = [

        {
            'name': 'Docker Nginx Server (HTTPS)',
            'url': 'https://localhost:8443'
        },
        {
            'name': 'Docker Server (without NGINX)',
            'url': 'http://localhost:8001'
        },
        {
            'name': 'Dev Server',
            'url': 'http://localhost:5001'
        },
        {
            'name': 'Dev Server',
            'url': 'http://localhost:5000'
        }
    ]

    app.security_schemes = {
        'ApiKeyAuth': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'X-API-Key',
        }
    }


def register_auth_handler(auth: HTTPTokenAuth) -> None:
    @auth.verify_token
    def verify_token(token: str) -> t.Union[AuthUser, None]:
        if re.match(RE_AUTH_TOKEN, token):
            user = AuthUser.find_by_token(token)
            return user
        return None


def register_blueprints(app: Flask) -> None:
    from reveal.webapi.ad import bp as ad_bp
    app.register_blueprint(ad_bp)

    from reveal.webapi.sysinfo.views import bp as sysinfo_bp
    app.register_blueprint(sysinfo_bp)

    from reveal.webapi.sysinfo.reportviews import report_bp as si_report_bp
    app.register_blueprint(si_report_bp)


