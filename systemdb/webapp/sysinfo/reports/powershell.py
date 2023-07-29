from flask import render_template, Response, url_for
from flask_login import login_required
from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief

from systemdb.core.models.sysinfo import Host
from systemdb.webapp.sysinfo.reports import ReportInfo

####################################################################
# Hosts with PowerShell 2.0 installed
####################################################################
@sysinfo_bp.route('/report/ps2', methods=['GET'])
@login_required
def hosts_report_ps2():
    hosts = Host.query.filter(Host.PS2Installed == True).all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_ps2_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_ps2_excel_full"))


@sysinfo_bp.route('/report/ps2/excel/full', methods=['GET'])
@login_required
def hosts_report_ps2_excel_full():
    hosts = Host.query.filter(Host.PS2Installed == True).all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-ps2-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


@sysinfo_bp.route('/report/ps2/excel/brief', methods=['GET'])
@login_required
def hosts_report_ps2_excel_brief():
    hosts = Host.query.filter(Host.PS2Installed == True).all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-ps2-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})



class ReportPS2Istalled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="PowerShell 2.0 Enabled",
            category="Hardening",
            tags=["Powershell", "Systemhardening", "Missing Security Feature", "BSI: SiSyPHus Win10"],
            description='Report all hosts where PowerShell Version 2.0 is installed / enabled.',
            views=[('view', url_for('sysinfo.hosts_report_ps2'))]
        )