from ....ma import ma
from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields


class ServicePermissionSearchSchema(ma.Schema):
    Accountname = fields.String(validate=Regexp(regex="[a-zA-Z0-9 \.\-\_]+"))
    Permission = fields.String(validate=Regexp(regex="[a-zA-Z0-9 \,\.\-\_]+"))
