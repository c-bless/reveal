from apiflask import Schema
from apiflask.fields import String
from apiflask.validators import Regexp

from reveal.core.regex import RE_SYSINFO_PRODUCT_NAME


class ProductNameSearchSchema(Schema):
    name = String(validate=Regexp(regex=RE_SYSINFO_PRODUCT_NAME))
