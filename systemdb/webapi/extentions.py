from apiflask import HTTPTokenAuth
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
auth = HTTPTokenAuth()
ma = Marshmallow()