from flask import Blueprint

import_bp = Blueprint('importer', __name__, template_folder="templates", url_prefix='/importer')

from reveal.webapp.importer.views import upload_post, upload, import_file_by_uid, import_all