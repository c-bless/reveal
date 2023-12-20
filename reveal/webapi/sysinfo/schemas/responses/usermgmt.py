from apiflask import Schema
from apiflask.fields import String

from reveal.webapi.extentions import ma
from reveal.webapi.sysinfo.schemas.responses.hosts import HostNestedSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import GroupNestedSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import UserNestedSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import GroupMemberNestedSchema


class UserGroupAssignment(Schema):

    Host = HostNestedSchema(many=False)
    Group = GroupNestedSchema(many=False)
    User = GroupMemberNestedSchema(many=False)


class GroupMembershipSchema(Schema):
    Host = ma.Nested(HostNestedSchema, many=False, allow_none=False)
    Group = ma.Nested(GroupNestedSchema, many=False, allow_none=False)
    Members = ma.Nested(UserNestedSchema, many=True, allow_none=False)