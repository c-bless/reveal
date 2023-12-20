
from apiflask import APIBlueprint


bp = APIBlueprint('Active Directory', 'ad_api' , url_prefix='/api/ad')

from reveal.webapi.ad.views.domain import *
from reveal.webapi.ad.views.groups import *
from reveal.webapi.ad.views.forest import *
from reveal.webapi.ad.views.computer import *
from reveal.webapi.ad.views.users import *
from reveal.webapi.ad.views.trusts import *
from reveal.webapi.ad.views.admins import *