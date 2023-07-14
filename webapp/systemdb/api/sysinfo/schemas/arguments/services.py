from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields

from webapp.systemdb.api.ma import ma


class ServicePermissionSearchSchema(ma.Schema):
    Accountname = fields.String(validate=Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$"))
    Permission = fields.String(validate=Regexp(regex="^([a-zA-Z0-9 \.\-\_]+)?$"))
