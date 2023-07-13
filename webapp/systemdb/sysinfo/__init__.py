from flask import Blueprint

sysinfo_bp = Blueprint('sysinfo', __name__, template_folder="templates", url_prefix='/sysinfo')

from webapp.systemdb.sysinfo.export_views import *

from webapp.systemdb.sysinfo.views.hosts import  *
from webapp.systemdb.sysinfo.views.products import  *
from webapp.systemdb.sysinfo.views.services import  *
from webapp.systemdb.sysinfo.views.shares import *
from webapp.systemdb.sysinfo.views.usermanagement import  *

from webapp.systemdb.sysinfo.reports import *
from webapp.systemdb.sysinfo.reports.smb import  *
from webapp.systemdb.sysinfo.reports.wsus import  *
from webapp.systemdb.sysinfo.reports.admins import  *
from webapp.systemdb.sysinfo.reports.updates import  *
from webapp.systemdb.sysinfo.reports.wsh import  *
from webapp.systemdb.sysinfo.reports.powershell import  *
from webapp.systemdb.sysinfo.reports.winlogon import  *
from webapp.systemdb.sysinfo.reports.services import  *
from webapp.systemdb.sysinfo.reports.usermgmt import  *
from webapp.systemdb.sysinfo.reports.printers import  *
