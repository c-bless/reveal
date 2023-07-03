from flask import render_template, Response, url_for
import datetime

from .. import sysinfo_bp
from ..export_func import generate_hosts_excel, generate_hosts_excel_brief, generate_eol_excel_brief, generate_eol_excel_full

from ...models.sysinfo import Host
from ...api.sysinfo.querries.updates import get_EoLInfo

####################################################################
# Hosts where last update has been installed for more that xxx days
####################################################################
@sysinfo_bp.route('/hosts/report/lastupdate/<int:days>', methods=['GET'])
def hosts_report_lastupdate(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_lastupdate_excel_brief", days=days),
                           download_url=url_for("sysinfo.hosts_report_lastupdate_excel_full", days=days))


@sysinfo_bp.route('/hosts/report/lastupdate/<int:days>/excel/full', methods=['GET'])
def hosts_report_lastupdate_excel_full(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-lastupdate-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


@sysinfo_bp.route('/hosts/report/lastupdate/<int:days>/excel/brief', methods=['GET'])
def hosts_report_lastupdate_excel_brief(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-lastupdate-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})



####################################################################
# List OS and matching hosts that reached the end of life
####################################################################

@sysinfo_bp.route('/hosts/report/eol/', methods=['GET'])
def hosts_report_eol():
    eol_matches = get_EoLInfo()
    return render_template('eol_list.html', eol_matches=eol_matches)

@sysinfo_bp.route('/hosts/report/eol/excel/brief', methods=['GET'])
def hosts_report_eol_excel_brief():
    eol_matches = get_EoLInfo()
    output = generate_eol_excel_brief(eol_matches=eol_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=eol-systems-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

@sysinfo_bp.route('/hosts/report/eol/excel/full', methods=['GET'])
def hosts_report_eol_excel_full():
    eol_matches = get_EoLInfo()
    output = generate_eol_excel_full(eol_matches=eol_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=eol-systems-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})