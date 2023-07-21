from flask import Blueprint

sysinfo_bp = Blueprint('sysinfo', __name__, template_folder="templates", url_prefix='/sysinfo')

from systemdb.webapp.sysinfo.export_views import *

from systemdb.webapp.sysinfo.views.hosts import  *
from systemdb.webapp.sysinfo.views.products import  *
from systemdb.webapp.sysinfo.views.services import  *
from systemdb.webapp.sysinfo.views.shares import *
from systemdb.webapp.sysinfo.views.usermanagement import  *

from systemdb.webapp.sysinfo.reports import *
from systemdb.webapp.sysinfo.reports.smb import  *
from systemdb.webapp.sysinfo.reports.wsus import  *
from systemdb.webapp.sysinfo.reports.admins import  *
from systemdb.webapp.sysinfo.reports.updates import  *
from systemdb.webapp.sysinfo.reports.wsh import  *
from systemdb.webapp.sysinfo.reports.powershell import  *
from systemdb.webapp.sysinfo.reports.winlogon import  *
from systemdb.webapp.sysinfo.reports.services import  *
from systemdb.webapp.sysinfo.reports.usermgmt import  *
from systemdb.webapp.sysinfo.reports.printers import  *
