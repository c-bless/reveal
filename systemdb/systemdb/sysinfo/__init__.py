from flask import Blueprint

sysinfo_bp = Blueprint('sysinfo', __name__, template_folder="templates", url_prefix='/sysinfo')

from .host_views import *
from .export_views import *
from .report_views import *