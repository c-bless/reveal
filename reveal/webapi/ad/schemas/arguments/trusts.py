
from apiflask import Schema
from apiflask.fields import String
from apiflask.fields import Boolean
from apiflask.validators import Regexp

from reveal.core.regex import RE_AD_DOMAINNAME
from reveal.core.regex import RE_AD_TRUSTS_SOURCE
from reveal.core.regex import RE_AD_TRUSTS_TARGET
from reveal.core.regex import RE_AD_TRUSTS_DIRECTION
from reveal.core.regex import RE_AD_DISTINGUISHED_NAME


class TrustSearchSchema(Schema):
    Source = String(required=False, validate=Regexp(regex=RE_AD_TRUSTS_SOURCE))
    InvertSource = Boolean(required=False)
    Target = String(required=False, validate=Regexp(regex=RE_AD_TRUSTS_TARGET))
    InvertTarget = Boolean(required=False)
    Direction = String(required=False, validate=Regexp(regex=RE_AD_TRUSTS_DIRECTION))
    InvertDirection = Boolean(required=False)
    Domain = String(required=False, validate=Regexp(regex=RE_AD_DOMAINNAME))
    InvertDomain = Boolean(required=False)
    DistinguishedName = String(required=False, validate=Regexp(regex=RE_AD_DISTINGUISHED_NAME))
    InvertDistinguishedName = Boolean(required=False)

    UplevelOnly = Boolean(required=False)
    UsesAESKeys = Boolean(required=False)
    UsesRC4Encryption = Boolean(required=False)
    TGTDelegation = Boolean(required=False)
    SIDFilteringForestAware = Boolean(required=False)
    SIDFilteringQuarantined = Boolean(required=False)
    SelectiveAuthentication = Boolean(required=False)
    DisallowTransivity = Boolean(required=False)
    ForestTransitive = Boolean(required=False)
    IntraForest = Boolean(required=False)
    IsTreeParent = Boolean(required=False)
    IsTreeRoot = Boolean(required=False)