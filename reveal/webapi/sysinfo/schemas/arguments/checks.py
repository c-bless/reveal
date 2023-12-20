from apiflask import Schema
from apiflask.fields import String
from apiflask.validators import Regexp

from reveal.core.regex import RE_SYSINFO_REGISTRYCHECK_NAME
from reveal.core.regex import RE_SYSINFO_CONFIGCHECK_NAME


class RegistryCheckByNameSearchSchema(Schema):
    Name = String(validate=Regexp(regex=RE_SYSINFO_REGISTRYCHECK_NAME))


class ConfigCheckByNameSearchSchema(Schema):
    Name = String(validate=Regexp(regex=RE_SYSINFO_CONFIGCHECK_NAME))
