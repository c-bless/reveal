from flask import render_template, Response, url_for
import datetime

from . import sysinfo_bp

from ..models.sysinfo import Host, Group

from .export_func import generate_hosts_excel


@sysinfo_bp.route('/hosts/reports/', methods=['GET'])
def hosts_reports():
    return render_template('report_list.html')


####################################################################
# Hosts with DefaultPassword in Registry
####################################################################
@sysinfo_bp.route('/hosts/report/winlogon', methods=['GET'])
def hosts_report_winlogon():
    hosts = Host.query.filter(Host.DefaultPassword != "").all()
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_report_winlogon_excel"))


@sysinfo_bp.route('/hosts/report/winlogon/excel', methods=['GET'])
def hosts_report_winlogon_excel():
    hosts = Host.query.filter(Host.DefaultPassword != "").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-winlogon.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


####################################################################
# Hosts where last update has been installed for more that xxx days
####################################################################
@sysinfo_bp.route('/hosts/report/lastupdate/<int:days>', methods=['GET'])
def hosts_report_lastupdate(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    return render_template('host_list.html', hosts=hosts,
                           download_url=url_for("sysinfo.hosts_report_lastupdate_excel", days=days))


@sysinfo_bp.route('/hosts/report/lastupdate/<int:days>/excel', methods=['GET'])
def hosts_report_lastupdate_excel(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    hosts = Host.query.filter(Host.LastUpdate <= delta).all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-winlogon.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


####################################################################
# Hosts with PowerShell 2.0 installed
####################################################################
@sysinfo_bp.route('/hosts/report/ps2', methods=['GET'])
def hosts_report_ps2():
    hosts = Host.query.filter(Host.PS2Installed == "True").all()
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_report_ps2_excel"))


@sysinfo_bp.route('/hosts/report/ps2/excel', methods=['GET'])
def hosts_report_ps2_excel():
    hosts = Host.query.filter(Host.PS2Installed == "True").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-ps2.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


####################################################################
# Hosts with enabled WSH
####################################################################
@sysinfo_bp.route('/hosts/report/wsh', methods=['GET'])
def hosts_report_wsh():
    hosts = Host.query.filter(Host.WSHEnabled == "Enabled").all()
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_report_wsh_excel"))


@sysinfo_bp.route('/hosts/report/wsh/excel', methods=['GET'])
def hosts_report_wsh_excel():
    hosts = Host.query.filter(Host.WSHEnabled == "Enabled").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsh-enabled.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

####################################################################
# Hosts with WSH enabled for remote connections
####################################################################
@sysinfo_bp.route('/hosts/report/wshremote', methods=['GET'])
def hosts_report_wshremote():
    hosts = Host.query.filter(Host.WSHRemote == "Enabled").all()
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_report_wshremote_excel"))


@sysinfo_bp.route('/hosts/report/wshremote/excel', methods=['GET'])
def hosts_report_wshremote_excel():
    hosts = Host.query.filter(Host.WSHRemote == "Enabled").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-wsh-remote.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


####################################################################
# Hosts with enabled SMBv1
####################################################################
@sysinfo_bp.route('/hosts/report/smbv1/excel', methods=['GET'])
def hosts_report_smbv1_excel():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-smbv1.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/repAnd just instantiate the flask-apispec with the Flask app.ort/smbv1', methods=['GET'])
def hosts_report_smbv1():
    hosts = Host.query.filter(Host.SMBv1Enabled == "True").all()
    output = generate_hosts_excel(hosts)
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_report_smbv1_excel"))


####################################################################
# Hosts with Domain Admins in local admin group
####################################################################
@sysinfo_bp.route('/hosts/report/domainadmin/excel', methods=['GET'])
def hosts_report_domainadmin_excel():
    groups = Group.query.filter(Group.SID == "S-1-5-32-544").all()
    host_ids = []
    for g in groups:
        for m in g.Members:
            if m.SID.endswith("-512"):
                host_ids.append(g.Host_id)
    hosts = Host.query.filter(Host.id.in_(host_ids)).all()

    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-smbv1.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/report/domainadmin', methods=['GET'])
def hosts_report_domainadmin():
    groups = Group.query.filter(Group.SID == "S-1-5-32-544").all()
    host_ids = []
    for g in groups:
        for m in g.Members:
            if m.SID.endswith("-512"):
                host_ids.append(g.Host_id)
    hosts = Host.query.filter(Host.id.in_(host_ids)).all()

    output = generate_hosts_excel(hosts)
    return render_template('host_list.html', hosts=hosts, download_url=url_for("sysinfo.hosts_report_domainadmin_excel"))

