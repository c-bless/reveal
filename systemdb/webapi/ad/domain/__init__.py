
from apiflask import APIBlueprint


bp = APIBlueprint('ActiveDirectory - Domain', 'ad_domain_api' , url_prefix='/api/ad')

from systemdb.webapi.ad.domain.views import *