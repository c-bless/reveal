from apiflask import Schema
from apiflask.fields import String
from apiflask.validators import Regexp

from systemdb.core.regex import RE_SYSINFO_SERVICE_ACCOUNTNAME
from systemdb.core.regex import RE_SYSINFO_SERVICE_PERMISSIONSTRING


class ServicePermissionSearchSchema(Schema):
    Accountname = String(validate=Regexp(regex=RE_SYSINFO_SERVICE_ACCOUNTNAME))
    Permission = String(validate=Regexp(regex=RE_SYSINFO_SERVICE_PERMISSIONSTRING))
