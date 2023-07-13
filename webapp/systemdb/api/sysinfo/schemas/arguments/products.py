from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields

from webapp.systemdb.api.ma import ma

class ProductNameSearchSchema(ma.Schema):
    name = fields.String(validate=Regexp(regex='^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'))
