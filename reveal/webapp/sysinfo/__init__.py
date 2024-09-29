from flask import Blueprint

sysinfo_bp = Blueprint('sysinfo', __name__, url_prefix='/sysinfo')

from reveal.webapp.sysinfo.views.export_views import *

from reveal.webapp.sysinfo.views.hosts import *
from reveal.webapp.sysinfo.views.products import *
from reveal.webapp.sysinfo.views.services import *
from reveal.webapp.sysinfo.views.shares import *
from reveal.webapp.sysinfo.views.usermanagement import *
from reveal.webapp.sysinfo.views.checks import *
from reveal.webapp.sysinfo.views.defender import *
from reveal.webapp.sysinfo.views.configreview import *

from reveal.webapp.sysinfo.reports import *
from reveal.webapp.sysinfo.reports.hardening import *
from reveal.webapp.sysinfo.reports.smb import *
from reveal.webapp.sysinfo.reports.wsus import *
from reveal.webapp.sysinfo.reports.admins import *
from reveal.webapp.sysinfo.reports.updates import *
from reveal.webapp.sysinfo.reports.wsh import *
from reveal.webapp.sysinfo.reports.powershell import *
from reveal.webapp.sysinfo.reports.winlogon import *
from reveal.webapp.sysinfo.reports.services import *
from reveal.webapp.sysinfo.reports.usermgmt import *
from reveal.webapp.sysinfo.reports.printers import *
