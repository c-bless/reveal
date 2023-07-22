from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields

from systemdb.core.regex import RE_SYSINFO_PRODUCT_NAME
from systemdb.webapp.api.ma import ma

class ProductNameSearchSchema(ma.Schema):
    name = fields.String(validate=Regexp(regex=RE_SYSINFO_PRODUCT_NAME))
