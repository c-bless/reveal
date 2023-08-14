from apiflask import Schema
from apiflask.fields import String, Integer
from apiflask.validators import Regexp

from systemdb.core.regex import RE_AD_DOMAINNAME
from systemdb.core.regex import RE_AD_DOMAIN_NETBIOSNAME

class ADComputerByDomainSearchSchema(Schema):
    Id = Integer(required=False)
    Name = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    Netbios = String(required=False, validate=Regexp(regex=RE_AD_DOMAIN_NETBIOSNAME))