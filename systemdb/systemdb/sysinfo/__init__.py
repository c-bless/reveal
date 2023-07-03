from flask import Blueprint

sysinfo_bp = Blueprint('sysinfo', __name__, template_folder="templates", url_prefix='/sysinfo')

from .host_views import *
from .export_views import *

from .reports.smb import *
from .reports.wsus import *
from .reports.admins import *
from .reports.updates import *
from .reports.wsh import *
from .reports.powershell import *
from .reports.winlogon import *
from .reports.services import *
from .reports.usermgmt import *
from .reports.printers import *

from .report_views import *
