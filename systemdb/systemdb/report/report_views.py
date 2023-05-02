from flask import render_template

from ..core.model import Host

from . import report_bp
from flask import make_response

@report_bp.route('/report/templates', methods=['GET'])
def templates_list():
    templates = Host.query.all()
    return render_template('host_list.html', hosts=hosts)

@report_bp.route('/hosts/<int:id>', methods=['GET'])
def host_detail(id):
    host = Host.query.get_or_404(id)
    return render_template('host_details.html', host=host)

