from apiflask import Schema
from apiflask.fields import String, Integer, Boolean
from apiflask.validators import Regexp

from reveal.core.regex import RE_AD_DOMAINNAME
from reveal.core.regex import RE_AD_DOMAIN_NETBIOSNAME
from reveal.core.regex import RE_AD_SPN
from reveal.core.regex import RE_AD_HOSTNAME
from reveal.core.regex import RE_AD_DESCRIPTION
from reveal.core.regex import RE_AD_DISTINGUISHED_NAME
from reveal.core.regex import RE_AD_OS
from reveal.core.regex import RE_AD_SAMACCOUNT
from reveal.core.regex import RE_AD_COMPUTER_GROUPNAME
from reveal.core.regex import RE_SID_ALLOWED_CHARS
from reveal.core.regex import RE_IP4_ALLOWED_CHARS
from reveal.core.regex import RE_IP6_ALLOWED_CHARS
from reveal.core.regex import RE_AD_OPERATION_MASTERROLE


class ADComputerBySPNSchema(Schema):
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    SPN = String(required=False, validate=Regexp(regex=RE_AD_SPN))
    NOT_SPN = String(required=False, validate=Regexp(regex=RE_AD_SPN))


class ADComputerSearchSchema(Schema):
    Id = Integer(required=False)
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    DNSHostName = String(required=False, validate=Regexp(regex=RE_AD_HOSTNAME))
    Description = String(required=False, validate=Regexp(regex=RE_AD_DESCRIPTION))
    DistinguishedName = String(required=False, validate=Regexp(regex=RE_AD_DISTINGUISHED_NAME))
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    Enabled = Boolean(required=False)
    OperatingSystem = String(required=False, validate=Regexp(regex=RE_AD_OS))
    SamAccountName = String(required=False, validate=Regexp(regex=RE_AD_SAMACCOUNT))
    PrimaryGroup = String(required=False, validate=Regexp(regex=RE_AD_COMPUTER_GROUPNAME))
    SID = String(required=False, validate=Regexp(regex=RE_SID_ALLOWED_CHARS))
    IPv4Address = String(required=False, validate=Regexp(regex=RE_IP4_ALLOWED_CHARS))
    IPv6Address = String(required=False, validate=Regexp(regex=RE_IP6_ALLOWED_CHARS))
    TrustedForDelegation = Boolean(required=False)
    TrustedToAuthForDelegation = Boolean(required=False)


class ADComputerByDomainSearchSchema(Schema):
    DomainId = Integer(required=False)
    InvertDomainId = Boolean(required=False)
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    InvertDomain = Boolean(required=False)
    NETBIOS = String(required=False, validate=Regexp(regex=RE_AD_DOMAIN_NETBIOSNAME))
    InvertNETBIOS = Boolean(required=False)


class ADDCSearchSchema(Schema):
    Name = String(required=False, validate=Regexp(regex=RE_AD_HOSTNAME))
    InvertName = Boolean(required=False)
    OperatingSystem = String(required=False, validate=Regexp(regex=RE_AD_OS))
    InvertOperatingSystem = Boolean(required=False)
    IPv4Address = String(required=False, validate=Regexp(regex=RE_IP4_ALLOWED_CHARS))
    InvertIPv4Address = Boolean(required=False)
    IPv6Address = String(required=False, validate=Regexp(regex=RE_IP6_ALLOWED_CHARS))
    InvertIPv6Address = Boolean(required=False)
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    InvertDomain = Boolean(required=False)
    IsGlobalCatalog  = Boolean(required=False)
    UseIsGlobalCatalog = Boolean(required=False)
    Enabled = Boolean(required=False)
    UseEnabled = Boolean(required=False)
