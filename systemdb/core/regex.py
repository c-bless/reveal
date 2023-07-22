RE_AUTH_TOKEN = "^([0-9a-zA-Z]+)$"

RE_SYSINFO_BUILDNUMBER = "[0-9]{0,2}[\.]{1}[0-9]{0,2}[\.]{1}[0-9]{0,5}"
RE_SYSINFO_HOSTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_PRINTERNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"

# Product related keys
RE_SYSINFO_PRODUCT_NAME = '^([a-zA-Z0-9 \\\.\-\:\(\)\_"]+)?$'


# service related keys
RE_SYSINFO_SERVICE_ACCOUNTNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"
RE_SYSINFO_SERVICE_PERMISSIONSTRING = "^([a-zA-Z0-9 \.\-\_]+)?$"

RE_AD_DOMAINNAME = "^([a-zA-Z0-9 \.\-\_]+)?$"