from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_
from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel_brief
from systemdb.core.export.excel.usermgmt import generate_group_members_excel

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP

from systemdb.core.models.sysinfo import Host, Group
from systemdb.core.reports import ReportInfo
from systemdb.core.querries.usermgmt import find_groups_where_domadm_is_localadmin
from systemdb.core.querries.usermgmt import find_hosts_where_domadm_is_localadmin
from systemdb.core.querries.usermgmt import find_groups_where_domadm_is_localadmin_with_host_filter
from systemdb.core.querries.usermgmt import find_hosts_where_domadm_is_localadmin_with_host_filter

from systemdb.webapp.sysinfo.forms.report.DomAdminReport import DomAdminReportForm


####################################################################
# Hosts with Domain Admins in local admin group
####################################################################
@sysinfo_bp.route('/report/domainadmin/excel/full', methods=['GET', 'POST'])
@login_required
def hosts_report_domainadmin_excel_full():
    hosts = find_hosts_where_domadm_is_localadmin()

    output = generate_hosts_excel(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-domadmin.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

@sysinfo_bp.route('/report/domainadmin/excel/brief', methods=['GET', 'POST'])
@login_required
def hosts_report_domainadmin_excel_brief():
    hosts = find_hosts_where_domadm_is_localadmin()

    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-domadmin-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })

@sysinfo_bp.route('/report/domainadmin/word/', methods=['GET', 'POST'])
@login_required
def hosts_report_domainadmin_word():
    hosts = find_hosts_where_domadm_is_localadmin()

    output = generate_hosts_excel_brief(hosts)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=hosts-with-domadmin-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/domainadmin/excel/memberships', methods=['GET'])
@login_required
def hosts_report_domainadmin_excel_memberships():
    groups = find_groups_where_domadm_is_localadmin()
    output = generate_group_members_excel(groups)
    return Response(output, mimetype="text/xlsx",
                    headers={"Content-disposition": "attachment; filename=groups-with-domainadmin-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


@sysinfo_bp.route('/report/domainadmin', methods=['GET', 'POST'])
@login_required
def hosts_report_domainadmin():

    form = DomAdminReportForm()

    if request.method == 'POST':
        filters = []
        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data

            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    filters.append(Host.SystemGroup.ilike("%" + systemgroup + "%"))
                else:
                    filters.append(Host.SystemGroup.notilike("%" + systemgroup + "%"))
            if len(location) > 0:
                if not invertLocation:
                    filters.append(Host.Location.ilike("%" + location + "%"))
                else:
                    filters.append(Host.Location.notilike("%" + location + "%"))

            groups = find_groups_where_domadm_is_localadmin_with_host_filter(host_filter=filters)

            if 'brief' in request.form:
                hosts = find_hosts_where_domadm_is_localadmin_with_host_filter(host_filter=filters)
                output = generate_hosts_excel_brief(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=hosts_brief-domadmin.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            if 'full' in request.form:
                hosts = find_hosts_where_domadm_is_localadmin_with_host_filter(host_filter=filters)
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=hosts-domadmin.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        else:
            groups = find_groups_where_domadm_is_localadmin()

    else:
        groups = find_groups_where_domadm_is_localadmin()

    return render_template('sysinfo/group/group_members_list_search.html', groups=groups,
                               report_title='"Local adminstrators" containing "domain adminstrators"',
                               form=form)



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
    autologon_hosts = Host.query.filter(Host.AutoAdminLogon == True).all()
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

    return render_template('sysinfo/host/host_list.html', hosts=hosts,
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