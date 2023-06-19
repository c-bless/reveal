from flask import render_template, Response, url_for

from .. import sysinfo_bp
from ..export_func import generate_hosts_excel

from ...models.sysinfo import Host


####################################################################
# Hosts with enabled SMBv1
####################################################################
@sysinfo_bp.route('/hosts/report/smbv1/excel/full', methods=['GET'])
def hosts_report_smbv1_excel_full():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-smbv1-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/report/smbv1/excel/brief', methods=['GET'])
def hosts_report_smbv1_excel_brief():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-smbv1-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/report/smbv1', methods=['GET'])
def hosts_report_smbv1():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_smbv1_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_smbv1_excel_full"))

