RE_AUTH_TOKEN = r"^([0-9a-zA-Z]+)$"
RE_AUTH_USERNAME = r'^([a-zA-Z0-9\.\-\_]+)?$'
RE_AUTH_PASSWORD = r'^([a-zA-Z0-9\,\!\?\.\-\_\@\%]+)?$'

RE_SID_ALLOWED_CHARS = r"^([S\-0-9]+)?$"
RE_IP4_ALLOWED_CHARS = r"^([0-9\.]+)?$"
RE_IP6_ALLOWED_CHARS = r"^([0-9a-fA-F\:]+)?$"

RE_SYSINFO_BUILDNUMBER = r"[0-9]{0,2}[\.]{1}[0-9]{0,2}[\.]{1}[0-9]{0,5}"
RE_SYSINFO_HOSTNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_PRINTERNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SYSTEMGROUP = r"^([a-zA-Z0-9 \.\-\_]+)?$"

# Product related keys
RE_SYSINFO_PRODUCT_NAME = r'^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'
RE_SYSINFO_PRODUCT_CAPTION = r'^([a-zA-Z0-9 \.\-\(\)\_]+)?$'
RE_SYSINFO_PRODUCT_VERSION = r'^([a-zA-Z0-9 \.\-\_]+)?$'
RE_SYSINFO_PRODUCT_HOST = r'^([a-zA-Z0-9 \.\-\_]+)?$'
RE_SYSINFO_PRODUCT_INSTALLLOCATION = r'^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'

# service related keys
RE_SYSINFO_SERVICE_ACCOUNTNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_PERMISSIONSTRING = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_STARTNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_SYSTEMNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_PATHNAME = r'^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'
RE_SYSINFO_SERVICE_DISPLAYNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_NAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_STARTED = r"^([a-zA-Z]+)?$"
RE_SYSINFO_SERVICE_STARTMODE = r"^([a-zA-Z0-9 \.\-\_]+)?$"

# Share related keys
RE_SYSINFO_SHARE_NAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SHARE_DESCRIPTION = r'^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'
RE_SYSINFO_SHARE_PATH = r'^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'

#TODO: Review DATA inputs
# ConfigChecks
RE_SYSINFO_CONFIGCHECK_NAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_COMPONENT = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_METHOD = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_KEY = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_RESULT = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_VALUE = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_CONFIGCHECK_MESSAGE = r"^([a-zA-Z0-9 \.\-\_]+)?$"

#TODO: Review DATA inputs
# Registry Checks
RE_SYSINFO_REGISTRYCHECK_NAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_CATEGORY = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_DESCRIPTION = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_TAGS = r"^([a-zA-Z0-9 \,\.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_PATH = r"^([a-zA-Z0-9 \:\\\.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_KEY = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_EXPECTED = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_REGISTRYCHECK_CURRENTVALUE = r"^([a-zA-Z0-9 \.\-\_]+)?$"

RE_AD_GROUP_SCOPE = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_GROUP_CATEGORY = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_GROUP_CN = r"^([a-zA-Z0-9 \.\-\_]+)?$"

# Active Directory
RE_AD_DOMAINNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_DOMAIN_NETBIOSNAME = r"^([a-zA-Z0-9\-]+)?$"
RE_AD_GROUPNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_FORESTNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_DISTINGUISHED_NAME = r"^([a-zA-Z0-9 \\\(\)\=\,\.\-\_]+)?$"
RE_AD_TRUSTS_SOURCE = r"^([a-zA-Z0-9 \\\(\)\=\,\.\-\_]+)?$"
RE_AD_TRUSTS_TARGET = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_TRUSTS_DIRECTION = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_SPN = r"^([a-zA-Z0-9 \\\,\.\-\_]+)?$"
RE_AD_HOSTNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_OS = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_DESCRIPTION = r"^([a-zA-Z0-9 \\\(\)\=\,\.\-\_]+)?$"
RE_AD_COMPUTER_GROUPNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"

RE_SID_USER_ACCOUNTS = r"^S-1-5-((32-\d*)|(21-\d*-\d*-\d*-\d*))$"
RE_AD_USER_NAME = r"^([a-zA-Z0-9\.\-\_]+[\$]?)?$"
RE_AD_SAMACCOUNT = r"^([a-zA-Z0-9\.\-\_]+[\$]?)?$"
RE_AD_USER_GIVENNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_USER_SURNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"
RE_AD_USER_DISPLAYNAME = r"^([a-zA-Z0-9 \.\-\_]+)?$"

RE_AD_SPN = r"^([a-zA-Z0-9 \\\.\-\_]+)?$"
RE_AD_OPERATION_MASTERROLE = r"^([a-zA-Z0-9 \.\-\_]+)?$"
