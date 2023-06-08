from ....ma import ma
from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields


class GroupNameSearchSchema(ma.Schema):
    id = fields.Integer(required=False)
    name = fields.String(validate=Regexp(regex="[a-zA-Z0-9 \.\-\_]+"))
