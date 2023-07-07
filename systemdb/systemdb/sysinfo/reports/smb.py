from flask import render_template, Response, url_for

from .. import sysinfo_bp
from ..export_func import generate_hosts_excel, generate_hosts_excel_brief

from ...models.sysinfo import Host
from . import ReportInfo

####################################################################
# Hosts with enabled SMBv1
####################################################################
@sysinfo_bp.route('/report/smbv1/excel/full', methods=['GET'])
def hosts_report_smbv1_excel_full():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-smbv1-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/smbv1/excel/brief', methods=['GET'])
def hosts_report_smbv1_excel_brief():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-smbv1-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/smbv1', methods=['GET'])
def hosts_report_smbv1():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_smbv1_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_smbv1_excel_full"))




class ReportSMBv1(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="SMBv1 Enabled",
            category="Systemhardening",
            tags=["Systemhardening", "SMB", "SMBv1"],
            description='Report all hosts where SMBv1 is installed / enabled.',
            views=[("view", url_for("sysinfo.hosts_report_smbv1"))]
        )