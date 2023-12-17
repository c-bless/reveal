from flask import render_template, Response, url_for,request
from flask_login import login_required
from sqlalchemy import and_
from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.powershell import generate_ps2_installed

from systemdb.core.models.sysinfo import Host
from systemdb.core.reports import ReportInfo

from systemdb.webapp.sysinfo.forms.report.PS2Report import PS2ReportForm

####################################################################
# Hosts with PowerShell 2.0 installed
####################################################################
@sysinfo_bp.route('/report/ps2', methods=['GET', 'POST'])
@login_required
def hosts_report_ps2():
    form = PS2ReportForm()

    filter = []
    filter.append(Host.PS2Installed == True)

    if request.method == 'POST':

        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data

            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    filter.append(Host.SystemGroup.ilike("%" + systemgroup + "%"))
                else:
                    filter.append(Host.SystemGroup.notilike("%" + systemgroup + "%"))
            if len(location) > 0:
                if not invertLocation:
                    filter.append(Host.Location.ilike("%" + location + "%"))
                else:
                    filter.append(Host.Location.notilike("%" + location + "%"))

            hosts = Host.query.filter(and_(*filter)).all()

            if 'excel' in request.form:
                output = generate_ps2_installed(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-ps2.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    else:
        hosts = Host.query.filter(and_(*filter)).all()
    return render_template('sysinfo/reports/PS2_list.html', hosts=hosts, form=form)

class ReportPS2Istalled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="PowerShell 2.0 Enabled",
            category="Hardening",
            tags=["Powershell", "Systemhardening", "Missing Security Feature", "BSI: SiSyPHus Win10"],
            description='Report all hosts where PowerShell Version 2.0 is installed / enabled.',
            views=[('view', url_for('sysinfo.hosts_report_ps2'))]
        )