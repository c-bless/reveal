from flask import Blueprint

report_bp = Blueprint('reports', __name__, template_folder="templates")

from .report_views import *