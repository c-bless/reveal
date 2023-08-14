from apiflask import Schema
from apiflask.fields import String

from systemdb.webapi.extentions import ma
from systemdb.webapi.sysinfo.schemas.responses.hosts import HostNestedSchema
from systemdb.webapi.sysinfo.schemas.responses.hosts import GroupNestedSchema
from systemdb.webapi.sysinfo.schemas.responses.hosts import UserNestedSchema


class UserGroupAssignment(Schema):

    Host = String(allow_none=False)
    Group = String(allow_none=False)
    User = String(allow_none=False)


class GroupMembershipSchema(Schema):
    Host = ma.Nested(HostNestedSchema, many=False, allow_none=False)
    Group = ma.Nested(GroupNestedSchema, many=False, allow_none=False)
    Members = ma.Nested(UserNestedSchema, many=True, allow_none=False)