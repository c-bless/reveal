from flask import Blueprint

host_bp = Blueprint('hosts', __name__, template_folder="templates")

from .host_views import *
from .export_views import *