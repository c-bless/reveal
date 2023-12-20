
from apiflask import APIBlueprint


bp = APIBlueprint('Sysinfo Collector', 'sysinfo_api' , url_prefix='/api/sysinfo')

from reveal.webapi.sysinfo.views.hosts import *
from reveal.webapi.sysinfo.views.services import *
from reveal.webapi.sysinfo.views.users import *
from reveal.webapi.sysinfo.views.software import *
from reveal.webapi.sysinfo.views.checks import *
from reveal.webapi.sysinfo.views.shares import *

