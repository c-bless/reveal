RE_AUTH_TOKEN = "^([0-9a-zA-Z]+)$"

RE_SYSINFO_BUILDNUMBER = "[0-9]{0,2}[\.]{1}[0-9]{0,2}[\.]{1}[0-9]{0,5}"
RE_SYSINFO_HOSTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_PRINTERNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"

# Product related keys
RE_SYSINFO_PRODUCT_NAME = '^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'
RE_SYSINFO_PRODUCT_CAPTION = '^([a-zA-Z0-9 \.\-\(\)\_]+)?$'
RE_SYSINFO_PRODUCT_VERSION = '^([a-zA-Z0-9 \.\-\_]+)?$'
RE_SYSINFO_PRODUCT_HOST = '^([a-zA-Z0-9 \.\-\_]+)?$'
RE_SYSINFO_PRODUCT_INSTALLLOCATION = '^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'

# service related keys
RE_SYSINFO_SERVICE_ACCOUNTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_PERMISSIONSTRING = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_STARTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_SYSTEMNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_PATHNAME = '^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'
RE_SYSINFO_SERVICE_DISPLAYNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_NAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_STARTED = "^([a-zA-Z]+)?$"
RE_SYSINFO_SERVICE_STARTMODE = "^([a-zA-Z0-9 \.\-\_]+)?$"

# Share related keys
RE_SYSINFO_Share_NAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_Share_DESCRIPTION = '^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'
RE_SYSINFO_Share_PATH = '^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'

#TODO: Review DATA inputs
# ConfigChecks
RE_SYSINFO_CONFIGCHECK_NAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_COMPONENT = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_METHOD = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_KEY = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_RESULT = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_VALUE = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_MESSAGE = "^([a-zA-Z0-9 \.\-\_]+)?$"

#TODO: Review DATA inputs
# Registry Checks
RE_SYSINFO_REGISTRYCHECK_NAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_CATEGORY = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_DESCRIPTION = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_TAGS = "^([a-zA-Z0-9 \,\.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_PATH = "^([a-zA-Z0-9 \:\\\.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_KEY = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_EXPECTED = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_CURRENTVALUE = "^([a-zA-Z0-9 \.\-\_]+)?$"


# Active Directory
RE_AD_DOMAINNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_GROUPNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_FORESTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_DISTINGUISHED_NAME = "^([a-zA-Z0-9 \\\(\)\=\,\.\-\_]+)?$"
RE_AD_TRUSTS_SOURCE = "^([a-zA-Z0-9 \\\(\)\=\,\.\-\_]+)?$"
RE_AD_TRUSTS_TARGET = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_TRUSTS_DIRECTION = "^([a-zA-Z0-9 \.\-\_]+)?$"

RE_AD_HOSTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_OS = "^([a-zA-Z0-9 \.\-\_]+)?$"

RE_SID_USER_ACCOUNTS = "^S-1-5-((32-\d*)|(21-\d*-\d*-\d*-\d*))$"
RE_AD_USER_NAME = "^([a-zA-Z0-9\.\-\_]+[\$]?)?$"
RE_AD_SAMACCOUNT = "^([a-zA-Z0-9\.\-\_]+[\$]?)?$"
RE_AD_USER_GIVENNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_USER_SURNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"

