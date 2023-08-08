import datetime
from flask import render_template, Response, url_for
from flask_login import login_required


from systemdb.core.models.sysinfo import Host
from systemdb.core.querries.updates import get_EoLInfo

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief
from systemdb.core.export.excel.eol import generate_eol_excel_brief
from systemdb.core.export.excel.eol import generate_eol_excel_full

from systemdb.core.reports import ReportInfo

####################################################################
# Hosts where last update has been installed for more that xxx days
####################################################################
@sysinfo_bp.route('/report/lastupdate/<int:days>', methods=['GET'])
@login_required
def hosts_report_lastupdate(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_lastupdate_excel_brief", days=days),
                           download_url=url_for("sysinfo.hosts_report_lastupdate_excel_full", days=days))


@sysinfo_bp.route('/report/lastupdate/<int:days>/excel/full', methods=['GET'])
@login_required
def hosts_report_lastupdate_excel_full(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-lastupdate-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


@sysinfo_bp.route('/report/lastupdate/<int:days>/excel/brief', methods=['GET'])
@login_required
def hosts_report_lastupdate_excel_brief(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-lastupdate-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})



class ReportLastUpdate(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Last update",
            category="Patch Management",
            tags=["Updates", "Missing Patches", "Windows Updates", "Patch Management"],
            description='Report all hosts where the last update was installed more that "n" days ago.',
            views=[("180 days", url_for("sysinfo.hosts_report_lastupdate" , days=180) ),
                  ("365 days", url_for("sysinfo.hosts_report_lastupdate" , days=365) )]
        )


####################################################################
# List OS and matching hosts that reached the end of life
####################################################################

@sysinfo_bp.route('/hosts/report/eol/', methods=['GET'])
@login_required
def hosts_report_eol():
    eol_matches = get_EoLInfo()
    return render_template('eol_list.html', eol_matches=eol_matches)

@sysinfo_bp.route('/hosts/report/eol/excel/brief', methods=['GET'])
@login_required
def hosts_report_eol_excel_brief():
    eol_matches = get_EoLInfo()
    output = generate_eol_excel_brief(eol_matches=eol_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=eol-systems-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

@sysinfo_bp.route('/hosts/report/eol/excel/full', methods=['GET'])
@login_required
def hosts_report_eol_excel_full():
    eol_matches = get_EoLInfo()
    output = generate_eol_excel_full(eol_matches=eol_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=eol-systems-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})



class ReportEOL(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="End-Of-Life - OS",
            category="Lifecycle Management",
            tags=["End-Of-Life", "EoL", "End-Of-Support", "Lifecycle Management", "Outdated OS"],
            description='Report all hosts which reached the End-of-Life / End-of-Support',
            views=[("view", url_for("sysinfo.hosts_report_eol"))]
        )