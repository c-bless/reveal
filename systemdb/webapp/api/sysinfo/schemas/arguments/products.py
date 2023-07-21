from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields

from systemdb.core.regex import SYSINFO_PRODUCT_NAME
from systemdb.webapp.api.ma import ma

class ProductNameSearchSchema(ma.Schema):
    name = fields.String(validate=Regexp(regex=SYSINFO_PRODUCT_NAME))
