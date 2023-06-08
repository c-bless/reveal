from ....ma import ma
from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields


class ProductNameSearchSchema(ma.Schema):
    name = fields.String(validate=Regexp(regex="[a-zA-Z0-9 \.\-\_]+"))
