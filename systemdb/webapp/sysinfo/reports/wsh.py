from flask import render_template, Response, url_for
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.webapp.sysinfo.export_func import generate_hosts_excel, generate_hosts_excel_brief
from systemdb.core.models.sysinfo import Host
from systemdb.webapp.sysinfo.reports import ReportInfo

####################################################################
# Hosts with enabled WSH
####################################################################
@sysinfo_bp.route('/report/wsh', methods=['GET'])
@login_required
def hosts_report_wsh():
    hosts = Host.query.filter(Host.WSHEnabled == "Enabled").all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_wsh_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_wsh_excel_full"))


@sysinfo_bp.route('/report/wsh/excel/full', methods=['GET'])
@login_required
def hosts_report_wsh_excel_full():
    hosts = Host.query.filter(Host.WSHEnabled == "Enabled").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsh-enabled-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


@sysinfo_bp.route('/report/wsh/excel/brief', methods=['GET'])
@login_required
def hosts_report_wsh_excel_brief():
    hosts = Host.query.filter(Host.WSHEnabled == "Enabled").all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsh-enabled-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})



class ReportWSHEnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="WSH Enabled",
            category="Systemhardening",
            tags=["Systemhardening", "WSH", "BSI: SiSyPHus Win10"],
            description='Report all hosts where WSH is enabled.',
            views=[("view", url_for("sysinfo.hosts_report_wsh"))]
        )

####################################################################
# Hosts with WSH enabled for remote connections
####################################################################
@sysinfo_bp.route('/report/wshremote', methods=['GET'])
@login_required
def hosts_report_wshremote():
    hosts = Host.query.filter(Host.WSHRemote == "Enabled").all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_wshremote_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_wshremote_excel_full"))


@sysinfo_bp.route('/report/wshremote/excel/full', methods=['GET'])
@login_required
def hosts_report_wshremote_excel_full():
    hosts = Host.query.filter(Host.WSHRemote == "Enabled").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsh-remote-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

@sysinfo_bp.route('/report/wshremote/excel/brief', methods=['GET'])
@login_required
def hosts_report_wshremote_excel_brief():
    hosts = Host.query.filter(Host.WSHRemote == "Enabled").all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsh-remote-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


class ReportWSHRemoteEnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="WSH Remote Enabled",
            category="Systemhardening",
            tags=["Systemhardening", "WSH", "BSI: SiSyPHus Win10"],
            description='Report all hosts where WSH remote access is enabled.',
            views=[("view", url_for("sysinfo.hosts_report_wshremote"))]
        )