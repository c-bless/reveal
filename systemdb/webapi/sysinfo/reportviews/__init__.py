
from apiflask import APIBlueprint

from systemdb.webapi.tags import T_REPORT_SYSINFO

report_bp = APIBlueprint('Reports - Sysinfo', 'sysinfo_report_api' , url_prefix='/api/reports/', tag=T_REPORT_SYSINFO)

from systemdb.webapi.sysinfo.reportviews.usermgmt import *
from systemdb.webapi.sysinfo.reportviews.hosts import *
from systemdb.webapi.sysinfo.reportviews.updates import *
