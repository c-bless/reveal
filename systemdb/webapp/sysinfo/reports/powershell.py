from flask import render_template, Response, url_for
from flask_login import login_required
from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.powershell import generate_ps2_installed

from systemdb.core.models.sysinfo import Host
from systemdb.core.reports import ReportInfo


####################################################################
# Hosts with PowerShell 2.0 installed
####################################################################
@sysinfo_bp.route('/report/ps2', methods=['GET'])
@login_required
def hosts_report_ps2():
    hosts = Host.query.filter(Host.PS2Installed == True).all()
    return render_template('sysinfo/reports/PS2_list.html', hosts=hosts)


@sysinfo_bp.route('/report/ps2/excel', methods=['GET'])
@login_required
def hosts_report_ps2_excel():
    hosts = Host.query.filter(Host.PS2Installed == True).all()
    output = generate_ps2_installed(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-ps2.xlsx",
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