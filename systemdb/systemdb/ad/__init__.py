from flask import Blueprint

ad_bp = Blueprint('ad', __name__, template_folder="templates")

from .ad_views import *