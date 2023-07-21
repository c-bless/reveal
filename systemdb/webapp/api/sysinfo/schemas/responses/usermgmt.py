from systemdb.webapp.api.ma import ma
from flask_marshmallow.fields import fields


class UserGroupAssignment(ma.Schema):

    Host = fields.String(allow_none=False)
    Group = fields.String(allow_none=False)
    User = fields.String(allow_none=False)