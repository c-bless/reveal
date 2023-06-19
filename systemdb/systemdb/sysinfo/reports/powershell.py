from flask import render_template, Response, url_for

from .. import sysinfo_bp
from ..export_func import generate_hosts_excel, generate_hosts_excel_brief

from ...models.sysinfo import Host


####################################################################
# Hosts with PowerShell 2.0 installed
####################################################################
@sysinfo_bp.route('/hosts/report/ps2', methods=['GET'])
def hosts_report_ps2():
    hosts = Host.query.filter(Host.PS2Installed == "True").all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_ps2_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_ps2_excel_full"))


@sysinfo_bp.route('/hosts/report/ps2/excel/full', methods=['GET'])
def hosts_report_ps2_excel_full():
    hosts = Host.query.filter(Host.PS2Installed == "True").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-ps2-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


@sysinfo_bp.route('/hosts/report/ps2/excel/brief', methods=['GET'])
def hosts_report_ps2_excel_brief():
    hosts = Host.query.filter(Host.PS2Installed == "True").all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-ps2-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
