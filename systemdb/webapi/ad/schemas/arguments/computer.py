from apiflask import Schema
from apiflask.fields import String, Integer, Boolean
from apiflask.validators import Regexp

from systemdb.core.regex import RE_AD_DOMAINNAME
from systemdb.core.regex import RE_AD_DOMAIN_NETBIOSNAME
from systemdb.core.regex import RE_AD_SPN
from systemdb.core.regex import RE_AD_HOSTNAME
from systemdb.core.regex import RE_AD_DESCRIPTION
from systemdb.core.regex import RE_AD_DISTINGUISHED_NAME
from systemdb.core.regex import RE_AD_OS
from systemdb.core.regex import RE_AD_SAMACCOUNT
from systemdb.core.regex import RE_AD_COMPUTER_GROUPNAME
from systemdb.core.regex import RE_SID_ALLOWED_CHARS
from systemdb.core.regex import RE_IP4_ALLOWED_CHARS
from systemdb.core.regex import RE_IP6_ALLOWED_CHARS


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
    NOT_DomainId = Integer(required=False)
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    NOT_Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    NETBIOS = String(required=False, validate=Regexp(regex=RE_AD_DOMAIN_NETBIOSNAME))
    NOT_NETBIOS = String(required=False, validate=Regexp(regex=RE_AD_DOMAIN_NETBIOSNAME))