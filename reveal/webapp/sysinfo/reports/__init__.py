from flask import render_template
from flask_login import login_required
from reveal.webapp.sysinfo import sysinfo_bp

from reveal.webapp.sysinfo.reports.admins import ReportDomAdminMemberOfLocalAdmin
from reveal.webapp.sysinfo.reports.admins import ReportAutologonIsLocalAdmin

from reveal.webapp.sysinfo.reports.usermgmt import ReportDirectDomainUserAssignment
from reveal.webapp.sysinfo.reports.usermgmt import ReportHostsByLocaluser
from reveal.webapp.sysinfo.reports.usermgmt import ReportLocalAdmins
from reveal.webapp.sysinfo.reports.usermgmt import ReportSIMATICUsers
from reveal.webapp.sysinfo.reports.usermgmt import ReportRDPUsers
from reveal.webapp.sysinfo.reports.usermgmt import ReportRemoteManagementUsers
from reveal.webapp.sysinfo.reports.usermgmt import ReportDCOMUsers
from reveal.webapp.sysinfo.reports.usermgmt import ReportPerformanceMonitorUsers

from reveal.webapp.sysinfo.reports.updates import ReportLastUpdate
from reveal.webapp.sysinfo.reports.updates import ReportEOL

from reveal.webapp.sysinfo.reports.powershell import ReportPS2Istalled
from reveal.webapp.sysinfo.reports.winlogon import ReportPWInWinlogon
from reveal.webapp.sysinfo.reports.smb import ReportSMBv1
from reveal.webapp.sysinfo.reports.smb import ReportSMBClientNoSigning
from reveal.webapp.sysinfo.reports.smb import ReportSMBServerNoSigning
from reveal.webapp.sysinfo.reports.wsh import ReportWSHEnabled, ReportWSHRemoteEnabled
from reveal.webapp.sysinfo.reports.wsus import ReportWSUSHttp
from reveal.webapp.sysinfo.reports.services import ReportUQSP
from reveal.webapp.sysinfo.reports.services import ReportServiceByPermission
from reveal.webapp.sysinfo.reports.services import ReportUQSP
from reveal.webapp.sysinfo.reports.services import ReportServiceByUsercontext
from reveal.webapp.sysinfo.reports.printers import ReportFilePrinterInstalled
from reveal.webapp.sysinfo.reports.services import ReportModifiableServices
from reveal.webapp.sysinfo.reports.hardening import ReportHotkeysEnabled


def get_usermgmt_report_list():
    report_plugin_list = []

    report_plugin_list.append(ReportDomAdminMemberOfLocalAdmin())
    report_plugin_list.append(ReportAutologonIsLocalAdmin())
    report_plugin_list.append(ReportDirectDomainUserAssignment())
    report_plugin_list.append(ReportHostsByLocaluser())
    report_plugin_list.append(ReportLocalAdmins())
    report_plugin_list.append(ReportSIMATICUsers())
    report_plugin_list.append(ReportRDPUsers())
    report_plugin_list.append(ReportRemoteManagementUsers())
    report_plugin_list.append(ReportDCOMUsers())
    report_plugin_list.append(ReportPerformanceMonitorUsers())

    return report_plugin_list


def get_patch_and_lifecyle_report_list():
    report_plugin_list = []

    report_plugin_list.append(ReportLastUpdate())
    report_plugin_list.append(ReportEOL())

    return report_plugin_list


def get_systemhardening_report_list():
    report_plugin_list = []

    report_plugin_list.append(ReportPS2Istalled())
    report_plugin_list.append(ReportPWInWinlogon())
    report_plugin_list.append(ReportSMBv1())
    report_plugin_list.append(ReportSMBClientNoSigning())
    report_plugin_list.append(ReportSMBServerNoSigning())
    report_plugin_list.append(ReportWSHEnabled())
    report_plugin_list.append(ReportWSHRemoteEnabled())
    report_plugin_list.append(ReportWSUSHttp())
    report_plugin_list.append(ReportUQSP())
    report_plugin_list.append(ReportServiceByPermission())
    report_plugin_list.append(ReportServiceByUsercontext())
    report_plugin_list.append(ReportFilePrinterInstalled())
    report_plugin_list.append(ReportHotkeysEnabled())
    report_plugin_list.append(ReportModifiableServices())

    return report_plugin_list


def get_report_list():
    report_plugin_list = []

    report_plugin_list.extend(get_usermgmt_report_list())
    report_plugin_list.extend(get_patch_and_lifecyle_report_list())
    report_plugin_list.extend(get_systemhardening_report_list())

    return report_plugin_list

def get_report_list_by_tag(tag):
    report_list = get_report_list()
    result = [r for r in report_list if tag.lower() in r.tags]
    return result


@sysinfo_bp.route('/reports/', methods=['GET'])
@login_required
def report_list():
    report_list = get_report_list()
    return render_template('sysinfo/reports/report_list.html', report_plugins=report_list)


@sysinfo_bp.route('/reports/updates-eol/', methods=['GET'])
@login_required
def update_eol_report_list():
    report_list = get_patch_and_lifecyle_report_list()
    return render_template('sysinfo/reports/report_list.html', report_plugins=report_list)


@sysinfo_bp.route('/reports/systemhardening/', methods=['GET'])
@login_required
def syshardening_report_list():
    report_list = get_systemhardening_report_list()
    return render_template('sysinfo/reports/report_list.html', report_plugins=report_list)


@sysinfo_bp.route('/reports/usermgmt/', methods=['GET'])
@login_required
def usermgmt_report_list():
    report_list = get_usermgmt_report_list()
    return render_template('sysinfo/reports/report_list.html', report_plugins=report_list)

