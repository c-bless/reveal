from flask import Blueprint

ad_bp = Blueprint('ad', __name__, template_folder="templates")

from webapp.systemdb.ad.domain_views import *
from webapp.systemdb.ad.forest_views import *
from webapp.systemdb.ad.computer_views import *
from webapp.systemdb.ad.user_group_views import *
from webapp.systemdb.ad.export_views import *