from apiflask import Schema
from apiflask.fields import String, Integer, Boolean
from apiflask.validators import Regexp

from systemdb.core.regex import RE_AD_GROUPNAME
from systemdb.core.regex import RE_AD_GROUP_CATEGORY
from systemdb.core.regex import RE_AD_GROUP_SCOPE
from systemdb.core.regex import RE_AD_DESCRIPTION
from systemdb.core.regex import RE_AD_DOMAINNAME
from systemdb.core.regex import RE_SID_ALLOWED_CHARS


class GroupSearchSchema(Schema):
    id = Integer(required=False)
    SamAccountName = String(required=False, validate=Regexp(regex=RE_AD_GROUPNAME))
    SID = String(required=False, validate=Regexp(regex=RE_SID_ALLOWED_CHARS))
    Description = String(required=False, validate=Regexp(regex=RE_AD_DESCRIPTION))
    GroupCategory = String(required=False, validate=Regexp(regex=RE_AD_GROUP_CATEGORY))
    GroupScope = String(required=False, validate=Regexp(regex=RE_AD_GROUP_SCOPE))
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    InvertSamAccountName = Boolean(required=False)
    InvertSID = Boolean(required=False)
    InvertDescription = Boolean(required=False)
    InvertGroupCategory = Boolean(required=False)
    InvertGroupScope = Boolean(required=False)
    InvertDomain = Boolean(required=False)