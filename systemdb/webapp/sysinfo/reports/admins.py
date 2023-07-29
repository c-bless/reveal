from flask import render_template, Response, url_for
from flask_login import login_required
from sqlalchemy import and_
from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief
from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP

from systemdb.core.models.sysinfo import Host, Group
from systemdb.webapp.sysinfo.reports import ReportInfo


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


@sysinfo_bp.route('/report/domainadmin/excel/full', methods=['GET'])
@login_required
def hosts_report_domainadmin_excel_full():
    hosts = get_domadmin_memberof_local_admin()

    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-domnadmin.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

@sysinfo_bp.route('/report/domainadmin/excel/brief', methods=['GET'])
@login_required
def hosts_report_domainadmin_excel_brief():
    hosts = get_domadmin_memberof_local_admin()

    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-domnadmin-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/domainadmin', methods=['GET'])
@login_required
def hosts_report_domainadmin():
    hosts = get_domadmin_memberof_local_admin()
    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_domainadmin_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_domainadmin_excel_full"))


class ReportDomAdminMemberOfLocalAdmin(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Domain Admins in local administrators group",
            category="Hardening",
            tags=["Domain Admins", "Local Admins", "User Assignments", "MemberOf", "Admins",
                 "Admin Privileges"],
            description='Report all hosts where "Domain Admins" are members of the local administrators group',
            views=[("view", url_for('sysinfo.hosts_report_domainadmin'))]
        )


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


@sysinfo_bp.route('/report/autologonadmin/excel/full', methods=['GET'])
@login_required
def hosts_report_autologonadmin_excel_full():
    hosts = get_autologon_admin()

    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-autologonadmin-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/autologonadmin/excel/brief', methods=['GET'])
@login_required
def hosts_report_autologonadmin_excel_brief():
    hosts = get_autologon_admin()

    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-autologonadmin-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/autologonadmin', methods=['GET'])
@login_required
def hosts_report_autologonadmin():
    hosts = get_autologon_admin()

    return render_template('host_list.html', hosts=hosts,
                           download_brief_url=url_for("sysinfo.hosts_report_autologonadmin_excel_brief"),
                           download_url=url_for("sysinfo.hosts_report_autologonadmin_excel_full"))



class ReportAutologonIsLocalAdmin(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Autologon as admin",
            category="Hardening",
            tags=["Autologon", "Local Admins", "User Assignments", "MemberOf", "Admins",
                 "Admin Privileges"],
            description='Report all hosts where the autologon user is member of the local administrator group.',
            views=[("view",url_for("sysinfo.hosts_report_autologonadmin"))]
        )