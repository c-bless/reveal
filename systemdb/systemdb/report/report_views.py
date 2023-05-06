from flask import render_template, abort, Response, redirect, url_for

from ..core.sysinfo_models import Host
from . import report_bp


@report_bp.route('/reports/templates', methods=['GET'])
def templates_list():
    #templates = Host.query.all()
    #return render_template('host_list.html', hosts=hosts)
    pass


@report_bp.route('/reports/WinlogonPW', methods=['GET'])
def winlogon_list():
    hosts = Host.query.filter(Host.DefaultPassword != "").all()
    return render_template('host_list.html', hosts=hosts)
