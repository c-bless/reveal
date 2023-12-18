from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief
from systemdb.core.export.excel.hosts import generate_wsus
from systemdb.core.models.sysinfo import Host
from systemdb.core.reports import ReportInfo

from systemdb.webapp.sysinfo.forms.report.WSUSReport import WSUSReportForm

####################################################################
# Hosts with WSUS over http
####################################################################
@sysinfo_bp.route('/report/wsus-http/', methods=['GET', 'POST'])
@login_required
def report_wsus_http():
    form = WSUSReportForm()

    host_filter = []
    host_filter.append(Host.WUServer.like('http://%'))

    if request.method == 'POST':

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

            hosts = Host.query.filter(and_(*host_filter)).all()

            if 'full' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-wsus-via-http-full.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'brief' in request.form:
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={"Content-disposition": "attachment; filename=hosts-with-wsus-via-http-brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'wsus' in request.form:
                output = generate_wsus(hosts)
                return Response(output, mimetype="text/xlsx",
                                headers={"Content-disposition": "attachment; filename=wsus-via-http.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    else:
        hosts = Host.query.filter(and_(*host_filter)).all()
    return render_template('sysinfo/reports/wsus_list.html', hosts=hosts, form=form,
                           report_name="WSUS via http")


class ReportWSUSHttp(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="WSUS via http",
            category="Systemhardening",
            tags=["Systemhardening", "WSUS", "Cleartext protocol"],
            description='Report all hosts where the WSUS server is configured to be reached via http',
            views=[("view", url_for("sysinfo.report_wsus_http"))]
        )