from apiflask import Schema
from apiflask.fields import String
from apiflask.validators import Regexp

from systemdb.core.regex import AD_DOMAINNAME
class ADDomainByNameSchema(Schema):
    name = String(required=True, validate=Regexp(regex=AD_DOMAINNAME))