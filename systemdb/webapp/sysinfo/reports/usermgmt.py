from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.core.models.sysinfo import Host, Group, GroupMember, User
from systemdb.core.querries.usermgmt import get_direct_domainuser_assignments
from systemdb.core.querries.usermgmt import find_group_local_admins
from systemdb.core.querries.usermgmt import find_rdp_groups
from systemdb.core.querries.usermgmt import find_SIMATIC_groups
from systemdb.core.querries.usermgmt import find_RemoteMgmtUser_groups
from systemdb.core.querries.usermgmt import find_DCOM_user_groups
from systemdb.core.querries.usermgmt import find_PerformanceMonitorUser_groups
from systemdb.core.querries.usermgmt import find_hosts_by_local_user
from systemdb.core.querries.usermgmt import find_local_admins_group_member


from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.usermgmt import generate_userassignment_excel
from systemdb.core.export.excel.usermgmt import generate_group_members_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.reports import ReportInfo
from systemdb.webapp.sysinfo.forms.report.UserMgmtReports import HostByLocalUserSearchForm
from systemdb.webapp.sysinfo.forms.report.UserMgmtReports import LocalAdminSearchForm
from systemdb.webapp.sysinfo.forms.report.UserMgmtReports import DirectAssignmentReportForm
from systemdb.webapp.sysinfo.forms.report.UserMgmtReports import LocalAdminSearchForm
from systemdb.webapp.sysinfo.forms.report.UserMgmtReports import LocalSIMATICSearchForm

####################################################################
# Hosts with Domain Admins in local admin group
####################################################################
@sysinfo_bp.route('/reports/usermgmt/assigment/', methods=['GET', 'POST'])
@login_required
def usermgmt_assignment_list():
    form = DirectAssignmentReportForm()
    host_filter = []

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

            members = get_direct_domainuser_assignments(host_filter=host_filter)

            if 'excel' in request.form:
                output = generate_userassignment_excel(members)

                return Response(output, mimetype="text/xlsx",
                                headers={"Content-disposition": "attachment; filename=direct-assigned-domainusers.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        members = []
    return render_template('sysinfo/reports/userassignment_list.html',members=members, form=form,
                           report_name="Direct user assignments")


class ReportDirectDomainUserAssignment(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Direct user assignments",
            category="User Management",
            tags=["User Management", "User Assignment", "Revoke of Permission"],
            description='Report all hosts which have domain users directly assigned instead of centrally managed views groups.',
            views=[("view", url_for("sysinfo.usermgmt_assignment_list"))]
        )


#####################################################################################
# Get hosts by local user
#####################################################################################
@sysinfo_bp.route('/reports/hosts/by-localuser/', methods=['GET','POST'])
@login_required
def report_hosts_by_localuser_list():
    form = HostByLocalUserSearchForm()
    host_filter = []

    if request.method == 'POST':
        if form.validate_on_submit():
            user_filter = form.Name.data

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

            hosts = find_hosts_by_local_user(username=user_filter, host_filter=host_filter)

            if 'excel' in request.form:
                output = generate_hosts_excel(hosts)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=hosts-by-localuser.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        else:
            hosts = []
    else:
        hosts = find_hosts_by_local_user()

    return render_template('sysinfo/reports/host_by_local_user.html',form=form, hosts=hosts,
                           report_name="Hosts By Localuser")



class ReportHostsByLocaluser(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hosts By Localuser",
            category="User Management",
            tags=["User Management", "Local Accounts"],
            description='Report all hosts which have the specified local account enabled.',
            views=[("view", url_for("sysinfo.report_hosts_by_localuser_list"))]
        )




####################################################################
# Members in local admin group
####################################################################

@sysinfo_bp.route('/reports/usermgmt/localadmins/', methods=['GET', 'POST'])
@login_required
def local_admin_assignment_list():
    form = LocalAdminSearchForm()

    host_filter = []
    user_filter = []

    if request.method == 'POST':
        username = form.Username.data
        domain = form.Domain.data
        hostname = form.Hostname.data
        invertUsername = form.InvertUsername.data
        invertDomain = form.InvertDomain.data
        invertHostname = form.InvertHostname.data

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
        if len(hostname) > 0:
            if invertHostname == False:
                host_filter.append(Host.Hostname.ilike("%" + hostname + "%"))
            else:
                host_filter.append(Host.Hostname.notilike("%" + hostname + "%"))
        if len(domain) > 0:
            if invertDomain == False:
                user_filter.append(GroupMember.Domain.ilike("%" + domain + "%"))
            else:
                user_filter.append(GroupMember.Domain.notilike("%" + domain + "%"))
        if len(username) > 0:
            if invertUsername == False:
                user_filter.append(GroupMember.Name.ilike("%" + username + "%"))
            else:
                user_filter.append(GroupMember.Name.notilike("%" + username + "%"))

        groups = find_group_local_admins(user_filter=user_filter, host_filter=host_filter)

        if 'excel' in request.form:
            output = generate_group_members_excel(groups=groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_local_admins.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        groups = find_group_local_admins()

    return render_template('sysinfo/reports/group_members_list.html', groups=groups, form=form,
                           report_name="Local Admins")


class ReportLocalAdmins(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="List local administrators",
            category="User Management",
            tags=["User Management", "Administrators", "Administartive Permission", "GroupMembers"],
            description='Report all members of local administrator groups.',
            views=[("view", url_for("sysinfo.local_admin_assignment_list"))]
        )


####################################################################
# Members in local SIMATIC groups
####################################################################
@sysinfo_bp.route('/reports/usermgmt/SIMATIC/', methods=['GET', 'POST'])
@login_required
def local_SIMATIC_users_list():
    form = LocalSIMATICSearchForm()

    host_filter = []

    if request.method == 'POST':
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
        groups = find_SIMATIC_groups(host_filter=host_filter)

        if 'excel' in request.form:
            output = generate_group_members_excel(groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_SIMATIC.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        groups = find_SIMATIC_groups(host_filter=host_filter)

    return render_template('sysinfo/reports/group_members_list.html', groups=groups, form=form,
                           report_name="List members of SIMATIC* groups")


class ReportSIMATICUsers(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="List members of SIMATIC* groups",
            category="User Management",
            tags=["User Management", "Siemens", "SIMATIC", "SIMATIC HMI", "SIMATIC HMI Viewer",
                  "OT", "ICS", "PCS7", "WinCC", "GroupMembers"],
            description='Report all members of Siemens SIMATIC groups.',
            views=[("view", url_for("sysinfo.local_SIMATIC_users_list"))]
        )


####################################################################
# Members in local SIMATIC groups
####################################################################

@sysinfo_bp.route('/reports/usermgmt/RDP/', methods=['GET'])
@login_required
def local_rdp_users_list():
    groups = find_rdp_groups()
    return render_template('sysinfo/group/group_members_list.html', groups=groups,
                           download_membership_url=url_for("sysinfo.local_rdp_users_excel_full"))


@sysinfo_bp.route('/report/usermgmt/RDP/excel/full', methods=['GET'])
@login_required
def local_rdp_users_excel_full():
    groups = find_rdp_groups()
    output = generate_group_members_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_RDP.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


class ReportRDPUsers(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of local "Remote Desktop Users" groups',
            category="User Management",
            tags=["User Management", "Remote Desktop Users", "RDP", "GroupMembers"],
            description='Report all members of local "Remote desktop Users" group.',
            views=[("view", url_for("sysinfo.local_rdp_users_list"))]
        )




####################################################################
# Members in local "Remote Management Users" groups
####################################################################

@sysinfo_bp.route('/reports/usermgmt/remotemgmtuser/', methods=['GET'])
@login_required
def local_remote_mgmt_users_list():
    groups = find_RemoteMgmtUser_groups()
    return render_template('sysinfo/group/group_members_list.html', groups=groups,
                           download_membership_url=url_for("sysinfo.local_remote_mgmt_users_excel_full"))


@sysinfo_bp.route('/report/usermgmt/remotemgmtuser/excel/full', methods=['GET'])
@login_required
def local_remote_mgmt_users_excel_full():
    groups = find_RemoteMgmtUser_groups()
    output = generate_group_members_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_remote_mgmt_users.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


class ReportRemoteManagementUsers(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Remote Management Users" groups',
            category="User Management",
            tags=["User Management", "Remote Management Users", "GroupMembers"],
            description='Report all members of "Remote Management Users" groups',
            views=[("view", url_for("sysinfo.local_remote_mgmt_users_list"))]
        )



####################################################################
# Members in local DCOM Users groups
####################################################################

@sysinfo_bp.route('/reports/usermgmt/dcom/', methods=['GET'])
@login_required
def local_dcom_users_list():
    groups = find_DCOM_user_groups()
    return render_template('sysinfo/group/group_members_list.html', groups=groups,
                           download_membership_url=url_for("sysinfo.local_dcom_users_excel_full"))


@sysinfo_bp.route('/report/usermgmt/dcom/excel/full', methods=['GET'])
@login_required
def local_dcom_users_excel_full():
    groups = find_DCOM_user_groups()
    output = generate_group_members_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_DCOM_users.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


class ReportDCOMUsers(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Distributed COM Users" groups',
            category="User Management",
            tags=["User Management", "Distributed COM Users", "GroupMembers"],
            description='Report all members of "Distributed COM Users',
            views=[("view", url_for("sysinfo.local_dcom_users_list"))]
        )



####################################################################
# Members in local Performance Monitor Users groups
####################################################################

@sysinfo_bp.route('/reports/usermgmt/performancemonitor/', methods=['GET'])
@login_required
def local_performance_monitor_users_list():
    groups = find_PerformanceMonitorUser_groups()
    return render_template('sysinfo/group/group_members_list.html', groups=groups,
                           download_membership_url=url_for("sysinfo.local_performance_monitor_users_excel_full"))


@sysinfo_bp.route('/report/usermgmt/performancemonitor/excel/full', methods=['GET'])
@login_required
def local_performance_monitor_users_excel_full():
    groups = find_PerformanceMonitorUser_groups()
    output = generate_group_members_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_PerformanceMonitorUsers.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


class ReportPerformanceMonitorUsers(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Performance Monitor Users" groups',
            category="User Management",
            tags=["User Management", "Performance Monitor Users", "GroupMembers"],
            description='Report all members of "Performance Monitor Users',
            views=[("view", url_for("sysinfo.local_performance_monitor_users_list"))]
        )