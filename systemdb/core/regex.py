RE_AUTH_TOKEN = "^([0-9a-zA-Z]+)$"

RE_SYSINFO_BUILDNUMBER = "[0-9]{0,2}[\.]{1}[0-9]{0,2}[\.]{1}[0-9]{0,5}"
RE_SYSINFO_HOSTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_PRINTERNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"

# Product related keys
RE_SYSINFO_PRODUCT_NAME = '^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'


# service related keys
RE_SYSINFO_SERVICE_ACCOUNTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_PERMISSIONSTRING = "^([a-zA-Z0-9 \.\-\_]+)?$"

# Registry Checks
RE_SYSINFO_REGISTRYCHECK_NAME = "^([a-zA-Z0-9 \.\-\_]+)?$"

# ConfigChecks
RE_SYSINFO_CONFIGCHECK_NAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_COMPONENT = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_METHOD = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_KEY = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_RESULT = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_VALUE = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_MESSAGE = "^([a-zA-Z0-9 \.\-\_]+)?$"


# Active Directory
RE_AD_DOMAINNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_GROUPNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_FORESTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"