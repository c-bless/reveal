from flask import Blueprint

auth_bp = Blueprint('auth', __name__, template_folder="templates", url_prefix='/')


from .views import profile, login, logout, index, change_pw_post