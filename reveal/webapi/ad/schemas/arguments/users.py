from apiflask import Schema
from apiflask.fields import String, Integer
from apiflask.validators import Regexp

from reveal.core.regex import RE_AD_DOMAINNAME
from reveal.core.regex import RE_AD_DOMAIN_NETBIOSNAME


class UserByDomainSearchSchema(Schema):
    id = Integer(required=False)
    Domainname = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    NETBIOS = String(required=False, validate=Regexp(regex=RE_AD_DOMAIN_NETBIOSNAME))
