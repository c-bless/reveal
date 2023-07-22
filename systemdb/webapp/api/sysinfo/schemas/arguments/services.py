from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields

from systemdb.core.regex import RE_SYSINFO_SERVICE_ACCOUNTNAME
from systemdb.core.regex import RE_SYSINFO_SERVICE_PERMISSIONSTRING

from systemdb.webapp.api.ma import ma


class ServicePermissionSearchSchema(ma.Schema):
    Accountname = fields.String(validate=Regexp(regex=RE_SYSINFO_SERVICE_ACCOUNTNAME))
    Permission = fields.String(validate=Regexp(regex=RE_SYSINFO_SERVICE_PERMISSIONSTRING))
