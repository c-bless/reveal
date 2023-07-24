
from apiflask import APIBlueprint


bp = APIBlueprint('Sysinfo Collector', 'sysinfo_api' , url_prefix='/api/sysinfo')

from systemdb.webapi.sysinfo.views.hosts import *
from systemdb.webapi.sysinfo.views.services import *
from systemdb.webapi.sysinfo.views.users import *
