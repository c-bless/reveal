from systemdb.webapp.api.ma import ma
from flask_marshmallow.fields import fields

class AuthErrorSchema(ma.Schema):
    code = fields.Integer(required=True)
    message = fields.String(allow_none=False)