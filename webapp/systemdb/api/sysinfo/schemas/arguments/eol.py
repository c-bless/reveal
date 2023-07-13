from ....ma import ma
from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields


class EoLSearchSchema(ma.Schema):
    BuildNumber = fields.String(validate=Regexp(regex="[0-9]{0,2}[\.]{1}[0-9]{0,2}[\.]{1}[0-9]{0,5}"))
