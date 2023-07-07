from flask import Blueprint

sysinfo_bp = Blueprint('sysinfo', __name__, template_folder="templates", url_prefix='/sysinfo')

from .export_views import *

from .views.hosts import *
from .views.products import *
from .views.services import *
from .views.shares import *
from .views.usermanagement import *

from .reports import report_list
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
