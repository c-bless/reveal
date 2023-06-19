from flask import render_template, Response, url_for
from sqlalchemy import and_
from .. import sysinfo_bp
from ..export_func import generate_hosts_excel, generate_hosts_excel_brief
from ..vars import SID_LOCAL_ADMIN_GROUP

from ...models.sysinfo import Host, Group


####################################################################
# Hosts with Domain Admins in local admin group
####################################################################
def get_domadmin_memberof_local_admin():
    groups = Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).all()
    host_ids = []
    for g in groups:
        for m in g.Members:
            if m.SID.endswith("-512"):
                host_ids.append(g.Host_id)
    hosts = Host.query.filter(Host.id.in_(host_ids)).all()
    return hosts


@sysinfo_bp.route('/hosts/report/domainadmin/excel/full', methods=['GET'])
def hosts_report_domainadmin_excel_full():
    hosts = get_domadmin_memberof_local_admin()

    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-domnadmin.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

@sysinfo_bp.route('/hosts/report/domainadmin/excel/brief', methods=['GET'])
def hosts_report_domainadmin_excel_brief():
    hosts = get_domadmin_memberof_local_admin()

    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-domnadmin-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/report/domainadmin', methods=['GET'])
def hosts_report_domainadmin():
    hosts = get_domadmin_memberof_local_admin()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_domainadmin_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_domainadmin_excel_full"))


####################################################################
# Hosts with autologon user in local admin group
####################################################################
def get_autologon_admin():
    result = []
    autologon_hosts = Host.query.filter(Host.AutoAdminLogon == 1).all()
    for h in autologon_hosts:
        defaultUser = h.DefaultUserName
        defaultDomain = h.DefaultDomain
        admins = Group.query.filter(and_(Group.SID == SID_LOCAL_ADMIN_GROUP, Group.Host_id == h.id)).first()
        for m in admins.Members:
            if defaultDomain == m.Domain and defaultUser == m.Name:
                result.append(h)
    return result


@sysinfo_bp.route('/hosts/report/autologonadmin/excel/full', methods=['GET'])
def hosts_report_autologonadmin_excel_full():
    hosts = get_autologon_admin()

    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-autologonadmin-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/report/autologonadmin/excel/brief', methods=['GET'])
def hosts_report_autologonadmin_excel_brief():
    hosts = get_autologon_admin()

    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-autologonadmin-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/hosts/report/autologonadmin', methods=['GET'])
def hosts_report_autologonadmin():
    hosts = get_autologon_admin()

    output = generate_hosts_excel_brief(hosts)
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_autologonadmin_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_autologonadmin_excel_full"))

