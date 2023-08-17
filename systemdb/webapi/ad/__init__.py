
from apiflask import APIBlueprint


bp = APIBlueprint('Active Directory', 'ad_api' , url_prefix='/api/ad')

from systemdb.webapi.ad.views.domain import *
from systemdb.webapi.ad.views.groups import *
from systemdb.webapi.ad.views.forest import *
from systemdb.webapi.ad.views.computer import *
from systemdb.webapi.ad.views.users import *
from systemdb.webapi.ad.views.trusts import *
from systemdb.webapi.ad.views.admins import *