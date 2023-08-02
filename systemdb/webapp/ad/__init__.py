from flask import Blueprint

ad_bp = Blueprint('ad', __name__, template_folder="templates")

from systemdb.webapp.ad.domain_views import *
from systemdb.webapp.ad.forest_views import *
from systemdb.webapp.ad.computer_views import *
from systemdb.webapp.ad.user_group_views import *
from systemdb.webapp.ad.export_views import *
from systemdb.webapp.ad.views.trusts import *