from apiflask import Schema
from apiflask.fields import String, Integer
from apiflask.validators import Regexp

from systemdb.core.regex import RE_AD_GROUPNAME


class GroupNameSearchSchema(Schema):
    id = Integer(required=False)
    name = String(required=True, validate=Regexp(regex=RE_AD_GROUPNAME))
