from flask import Blueprint

import_bp = Blueprint('importer', __name__, template_folder="templates", url_prefix='/importer')

from .views import upload_post, upload, import_file_byname, import_all