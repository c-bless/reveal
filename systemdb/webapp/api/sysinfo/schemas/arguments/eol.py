from systemdb.core.regex import RE_SYSINFO_BUILDNUMBER
from systemdb.webapp.api.ma import ma
from marshmallow.validate import Regexp
from flask_marshmallow.fields import fields

class EoLSearchSchema(ma.Schema):
    BuildNumber = fields.String(validate=Regexp(regex=RE_SYSINFO_BUILDNUMBER))
