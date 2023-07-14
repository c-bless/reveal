from flask_marshmallow.fields import fields

from webapp.systemdb.api.ma import ma


class LoginUserSchema(ma.Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)