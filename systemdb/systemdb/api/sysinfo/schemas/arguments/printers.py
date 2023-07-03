from ....ma import ma
from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields


class PrinterMatchSearchSchema(ma.Schema):
    names = fields.List(fields.String(validate=Regexp(regex="[a-zA-Z0-9 \.\-\_]+")))
