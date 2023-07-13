from flask_marshmallow.fields import fields

from webapp.systemdb.api.ma import ma


class AuthUserSchema(ma.Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)