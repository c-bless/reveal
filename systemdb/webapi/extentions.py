from apiflask import HTTPTokenAuth
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
auth = HTTPTokenAuth(scheme='ApiKey', header='X-API-KEY', security_scheme_name='ApiKeyAuth')
ma = Marshmallow()