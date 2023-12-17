from flask import render_template, Response, url_for, request
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief
from systemdb.core.export.excel.winlogon import generate_winlogon_excel
from systemdb.webapp.sysinfo.forms.report.RegistryReports import WinlogonReportForm
from systemdb.core.models.sysinfo import Host
from systemdb.core.reports import ReportInfo

####################################################################
# Hosts with DefaultPassword in Registry
####################################################################
@sysinfo_bp.route('/report/winlogon', methods=['GET', 'POST'])
@login_required
def hosts_report_winlogon():

    host_filter = []
    host_filter.append(Host.DefaultPassword != "")

    form = WinlogonReportForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data

            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    host_filter.append(Host.SystemGroup.ilike("%" + systemgroup + "%"))
                else:
                    host_filter.append(Host.SystemGroup.notilike("%" + systemgroup + "%"))
            if len(location) > 0:
                if not invertLocation:
                    host_filter.append(Host.Location.ilike("%" + location + "%"))
                else:
                    host_filter.append(Host.Location.notilike("%" + location + "%"))

            hosts = Host.query.filter(*host_filter).all()

            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-winlogon-brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-winlogon-full.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'winlogon' in request.form:
                output = generate_winlogon_excel(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-winlogon-values.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        hosts = Host.query.filter(*host_filter).all()

    return render_template('sysinfo/reports/host_with_winlogon.html', hosts=hosts, form=form)


class ReportPWInWinlogon(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Password in Winlogon",
            category="Systemhardening",
            tags=["Cleartext password", "Missconfigured Autologon", "Winlogon", "Registry"],
            description='Report all hosts where a password is stored in clear text in Windows Registry',
            views=[("view", url_for("sysinfo.hosts_report_winlogon"))]
        )