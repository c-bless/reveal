from apiflask import Schema
from apiflask.fields import String
from apiflask.validators import Regexp

from reveal.core.regex import RE_SYSINFO_HOSTNAME

class HostByNameSearchSchema(Schema):
    name = String(required=True, validate=Regexp(regex=RE_SYSINFO_HOSTNAME))

class HostByIPSearchSchema(Schema):
    ip = String(required=True)