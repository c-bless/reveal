from flask import render_template
from flask_login import login_required
from systemdb.webapp.ad import ad_bp
from systemdb.webapp.ad.reports.admins import ReportDomainAdminGroups


def get_report_list():
    report_plugin_list = []

    report_plugin_list.extend(get_report_usermgmt_list())

    return report_plugin_list


def get_report_usermgmt_list():
    report_plugin_list = []

    report_plugin_list.append(ReportDomainAdminGroups())

    return report_plugin_list


@ad_bp.route('/reports/', methods=['GET'])
@login_required
def report_list():
    report_list = get_report_list()
    return render_template('report_list.html', report_plugins=report_list)


@ad_bp.route('/reports/groupmembers/', methods=['GET'])
@login_required
def usermgmt_report_list():
    report_list = get_report_usermgmt_list()
    return render_template('report_list.html', report_plugins=report_list)

