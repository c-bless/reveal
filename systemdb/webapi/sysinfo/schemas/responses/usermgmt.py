
from apiflask import Schema
from apiflask.fields import String
class UserGroupAssignment(Schema):

    Host = String(allow_none=False)
    Group = String(allow_none=False)
    User = String(allow_none=False)