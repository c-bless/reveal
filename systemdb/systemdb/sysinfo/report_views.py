from flask import render_template

from . import sysinfo_bp


@sysinfo_bp.route('/hosts/reports/', methods=['GET'])
def hosts_reports():
    return render_template('report_list.html')
