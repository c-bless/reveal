from flask import Blueprint

auth_bp = Blueprint('auth', __name__, url_prefix='/')

from reveal.webapp.auth.views import profile, login, logout, index, change_pw_post
