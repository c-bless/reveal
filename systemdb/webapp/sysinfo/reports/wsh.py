from flask import render_template, Response, url_for, request
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief
from systemdb.core.models.sysinfo import Host
from systemdb.core.reports import ReportInfo
from systemdb.webapp.sysinfo.forms.report.WSHReports import WSHReportForm


####################################################################
# Hosts with enabled WSH
####################################################################
@sysinfo_bp.route('/report/wsh', methods=['GET', 'POST'])
@login_required
def hosts_report_wsh():
    host_filter = []
    host_filter.append(Host.WSHEnabled == True)

    form = WSHReportForm()

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
                                headers={
                                    "Content-disposition": "attachment; filename=hosts-with-wsh-enabled-brief.xlsx",
                                    "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-wsh-enabled-full.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        hosts = Host.query.filter(*host_filter).all()

    return render_template('sysinfo/reports/host_report_list.html', hosts=hosts, form=form,
                           report_name="WSH Enabled")



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
@sysinfo_bp.route('/report/wshremote', methods=['GET', 'POST'])
@login_required
def hosts_report_wshremote():
    host_filter = []
    host_filter.append(Host.WSHEnabled == True)

    form = WSHReportForm()

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
                                headers={"Content-disposition": "attachment; filename=hosts-with-wsh-remote-brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-wsh-remote-full.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        hosts = Host.query.filter(*host_filter).all()

    return render_template('sysinfo/reports/host_report_list.html', hosts=hosts, form=form,
                           report_name="WSH Remote Enabled")


class ReportWSHRemoteEnabled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="WSH Remote Enabled",
            category="Systemhardening",
            tags=["Systemhardening", "WSH", "BSI: SiSyPHus Win10"],
            description='Report all hosts where WSH remote access is enabled.',
            views=[("view", url_for("sysinfo.hosts_report_wshremote"))]
        )