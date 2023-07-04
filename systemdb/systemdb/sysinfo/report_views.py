from flask import render_template
from . import sysinfo_bp

from .reports import get_report_list

@sysinfo_bp.route('/hosts/reports/', methods=['GET'])
def hosts_reports():

    get_report_list()
    return render_template('report_list.html', report_plugins=get_report_list())
