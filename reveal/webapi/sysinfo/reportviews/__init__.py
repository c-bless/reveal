
from apiflask import APIBlueprint

from reveal.webapi.tags import T_REPORT_SYSINFO

report_bp = APIBlueprint('Reports - Sysinfo', 'sysinfo_report_api' , url_prefix='/api/reports/', tag=T_REPORT_SYSINFO)

from reveal.webapi.sysinfo.reportviews.usermgmt import *
from reveal.webapi.sysinfo.reportviews.hosts import *
from reveal.webapi.sysinfo.reportviews.updates import *
