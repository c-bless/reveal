from flask import render_template
from flask_login import login_required
from reveal.webapp.ad import ad_bp
from reveal.webapp.ad.reports.admins import ReportDomainAdminGroups
from reveal.webapp.ad.reports.admins import ReportEnterpriseAdminGroups
from reveal.webapp.ad.reports.admins import ReportSchemaAdminGroups
from reveal.webapp.ad.reports.spn import ReportComputerBySPN
from reveal.webapp.ad.reports.delegations import ReportComputerByUnconstraintDelegation
from reveal.webapp.ad.reports.delegations import ReportUserByUnconstraintDelegation
from reveal.webapp.ad.reports.delegations import ReportUserByConstraintDelegation

from reveal.webapp.ad.reports.user import ReportUserBadPwCountGtN
from reveal.webapp.ad.reports.user import ReportUserPWExpired
from reveal.webapp.ad.reports.user import ReportUserPWnotRequired
from reveal.webapp.ad.reports.user import ReportUserPWNeverExpires
from reveal.webapp.ad.reports.siemens import ReportSIMATICGroups


def get_report_list():
    report_plugin_list = []
    report_plugin_list.extend(get_report_usermgmt_list())
    report_plugin_list.append(ReportComputerBySPN())
    report_plugin_list.extend(get_report_delegation_list())
    return report_plugin_list


def get_report_usermgmt_list():
    report_plugin_list = []
    report_plugin_list.append(ReportDomainAdminGroups())
    report_plugin_list.append(ReportEnterpriseAdminGroups())
    report_plugin_list.append(ReportSchemaAdminGroups())
    report_plugin_list.append(ReportUserBadPwCountGtN())
    report_plugin_list.append(ReportUserPWExpired())
    report_plugin_list.append(ReportUserPWnotRequired())
    report_plugin_list.append(ReportSIMATICGroups())
    report_plugin_list.append(ReportUserPWNeverExpires())
    return report_plugin_list



def get_report_delegation_list():
    report_plugin_list = []
    report_plugin_list.append(ReportComputerByUnconstraintDelegation())
    report_plugin_list.append(ReportUserByUnconstraintDelegation())
    report_plugin_list.append(ReportUserByConstraintDelegation())
    return report_plugin_list


@ad_bp.route('/reports/', methods=['GET'])
@login_required
def report_list():
    report_list = get_report_list()
    return render_template('ad/reports/report_list.html', report_plugins=report_list)


@ad_bp.route('/reports/groupmembers/', methods=['GET'])
@login_required
def usermgmt_report_list():
    report_list = get_report_usermgmt_list()
    return render_template('ad/reports/report_list.html', report_plugins=report_list)

