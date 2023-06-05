from ....ma import ma
from flask_marshmallow import fields

class ProductSearchNameSchema(ma.Schema):
    name = fields.fields.String()
