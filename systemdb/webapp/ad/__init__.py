from flask import Blueprint

ad_bp = Blueprint('ad', __name__, template_folder="templates")

from systemdb.webapp.ad.reports import report_list, get_report_usermgmt_list
from systemdb.webapp.ad.views.domain import *
from systemdb.webapp.ad.views.forest import *
from systemdb.webapp.ad.views.computer import *
from systemdb.webapp.ad.views.usermgmt import *
from systemdb.webapp.ad.views.export import *
from systemdb.webapp.ad.views.trusts import *