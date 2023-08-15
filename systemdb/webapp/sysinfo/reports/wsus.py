from flask import render_template, Response, url_for
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief
from systemdb.core.export.excel.hosts import generate_wsus
from systemdb.core.models.sysinfo import Host
from systemdb.core.reports import ReportInfo

####################################################################
# Hosts with WSUS over http
####################################################################
@sysinfo_bp.route('/report/wsus-http/excel/full', methods=['GET'])
@login_required
def report_wsus_http_excel_hosts_full():
    hosts = Host.query.filter(Host.WUServer.like('http://%'))
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsus-via-http.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/wsus-http/excel/brief', methods=['GET'])
@login_required
def report_wsus_http_excel_hosts_brief():
    hosts = Host.query.filter(Host.WUServer.like('http://%'))
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsus-via-http.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })



@sysinfo_bp.route('/report/wsus-http/excel/wsus', methods=['GET'])
@login_required
def report_wsus_http_excel_wsus():
    hosts = Host.query.filter(Host.WUServer.like('http://%'))
    output = generate_wsus(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=wsus-via-http.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/wsus-http/', methods=['GET'])
@login_required
def report_wsus_http():
    hosts = Host.query.filter(Host.WUServer.like('http://%'))
    return render_template('report_wsus_list.html', hosts=hosts)




class ReportWSUSHttp(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="WSUS via http",
            category="Systemhardening",
            tags=["Systemhardening", "WSUS", "Cleartext protocol"],
            description='Report all hosts where the WSUS server is configured to be reached via http',
            views=[("view", url_for("sysinfo.report_wsus_http"))]
        )