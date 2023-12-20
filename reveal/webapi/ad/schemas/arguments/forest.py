from apiflask import Schema
from apiflask.fields import String
from apiflask.validators import Regexp

from reveal.core.regex import RE_AD_FORESTNAME


class ADForestByNameSchema(Schema):
    name = String(required=True, validate=Regexp(regex=RE_AD_FORESTNAME))