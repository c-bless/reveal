from flask import Blueprint

ad_bp = Blueprint('ad', __name__, template_folder="templates")

from .domain_views import *
from .forest_views import *
from .computer_views import *
from .user_group_views import *
from .export_views import *