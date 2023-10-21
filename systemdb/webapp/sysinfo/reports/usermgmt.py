from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.core.models.sysinfo import Host, Group, GroupMember, User
from systemdb.core.querries.usermgmt import get_direct_domainuser_assignments
from systemdb.core.querries.usermgmt import find_local_admins
from systemdb.core.querries.usermgmt import find_rdp_groups
from systemdb.core.querries.usermgmt import find_SIMATIC_groups
from systemdb.core.querries.usermgmt import find_RemoteMgmtUser_groups
from systemdb.core.querries.usermgmt import find_DCOM_user_groups
from systemdb.core.querries.usermgmt import find_PerformanceMonitorUser_groups


from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.core.export.excel.usermgmt import generate_userassignment_excel
from systemdb.core.export.excel.usermgmt import generate_group_members_excel
from systemdb.core.export.excel.hosts import generate_hosts_excel
from systemdb.core.reports import ReportInfo
from systemdb.webapp.sysinfo.forms.hosts import HostByLocalUserSearchForm
from systemdb.webapp.sysinfo.forms.groups import LocalAdminSearchForm


####################################################################
# Hosts with Domain Admins in local admin group
####################################################################



@sysinfo_bp.route('/reports/usermgmt/assigment/', methods=['GET'])
@login_required
def usermgmt_assignment_list():
    members = get_direct_domainuser_assignments()
    return render_template('sysinfo/reports/userassignment_list.html',members=members)


@sysinfo_bp.route('/report/usermgmt/assignment/excel/full', methods=['GET'])
@login_required
def usermgmt_assignment_excel_full():
    members = get_direct_domainuser_assignments()
    output = generate_userassignment_excel(members)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=direct-assigned-domainusers.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


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

    if request.method == 'POST':
        if form.validate_on_submit():
            user_filter = form.Name.data
            if len(user_filter) > 0:
                users = User.query.filter(and_(
                    User.LocalAccount == True,
                    User.Name.ilike("%"+user_filter+"%"),
                    User.Disabled == False
                )).all()
            else:
                users = User.query.filter(and_(
                    User.LocalAccount == True,
                    User.Disabled == False
                )).all()
            hosts = [u.Host for u in users]
            hosts_unique = []
            host_ids = []
            for h in hosts:
                if h.id not in host_ids:
                    host_ids.append(h.id)
                    hosts_unique.append(h)

            if 'download' in request.form:
                output = generate_hosts_excel(hosts_unique)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=hosts-by-localuser.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
            return render_template('sysinfo/reports/host_by_local_user.html', form=form, hosts=hosts_unique)
        else:
            return render_template('sysinfo/reports/host_by_local_user.html', form=form, hosts=[])
    else:
        users = User.query.filter(and_(
            User.LocalAccount == True,
            User.Disabled == False
        )).all()
        hosts = [u.Host for u in users]
        hosts_unique = []
        host_ids = []
        for h in hosts:
            if h.id not in host_ids:
                host_ids.append(h.id)
                hosts_unique.append(h)

    return render_template('sysinfo/reports/host_by_local_user.html',form=form, hosts=hosts_unique)



class ReportHostsByLocaluser(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Hosts By Localuser",
            category="User Management",
            tags=["User Management", "Local Accounts"],
            description='Report all hosts which have the specified local account enabled.',
            views=[("view", url_for("sysinfo.report_hosts_by_localuser_list"))]
        )



#####################################################################################
# Get local admins
#####################################################################################
@sysinfo_bp.route('/reports/localadmins/', methods=['GET','POST'])
@login_required
def report_localadmin_list():
    form = LocalAdminSearchForm()

    if request.method == 'POST':
        username = form.Username.data
        domain = form.Domain.data
        hostname = form.Hostname.data
        invertUsername = form.InvertUsername.data
        invertDomain = form.InvertDomain.data
        invertHostname = form.InvertHostname.data

        filters = []
        if len(hostname) > 0 :
            if invertHostname == False:
                hosts = Host.query.filter(Host.Hostname.ilike("%"+hostname+"%")).all()
            else:
                hosts = Host.query.filter(Host.Hostname.notilike("%"+hostname+"%")).all()
            host_ids = [h.id for h in hosts]

            local_admin_groups = Group.query.filter(and_(
                Group.SID == SID_LOCAL_ADMIN_GROUP,
                Group.Host_id.in_(host_ids)
            )).all()
            group_ids = [g.id for g in local_admin_groups]
        else:
            local_admin_groups = Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).all()
            group_ids = [g.id for g in local_admin_groups]
        if len(domain) > 0 :
            if invertDomain == False:
                filters.append(GroupMember.Domain.ilike("%"+domain+"%"))
            else:
                filters.append(GroupMember.Domain.notilike("%"+domain+"%"))
        if len(username) > 0:
            if invertUsername == False:
                filters.append(GroupMember.Name.ilike("%" + username + "%"))
            else:
                filters.append(GroupMember.Name.notilike("%" + username + "%"))
        filters.append(GroupMember.Group_id.in_(group_ids))
        members = GroupMember.query.filter(and_(*filters)).all()
        print(members)
    else:
        local_admin_groups = Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).all()
        group_ids = [g.id for g in local_admin_groups]

        members = GroupMember.query.all()

    return render_template('sysinfo/group/local_admin_list.html',form=form, members=members)


class ReportHostsByLocalAdmin(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Local Admin (search form)",
            category="User Management",
            tags=["User Management", "Local Accounts", "GroupMembers"],
            description='Report members of local administrators group.',
            views=[("view", url_for("sysinfo.report_localadmin_list"))]
        )


####################################################################
# Members in local admin group
####################################################################

@sysinfo_bp.route('/reports/usermgmt/localadmins/', methods=['GET'])
@login_required
def local_admin_assignment_list():
    groups = find_local_admins()
    return render_template('sysinfo/group/group_members_list.html', groups=groups,
                           download_membership_url=url_for("sysinfo.local_admin_assignment_excel_full"))


@sysinfo_bp.route('/report/usermgmt/localadmins/excel/full', methods=['GET'])
@login_required
def local_admin_assignment_excel_full():
    groups = find_local_admins()
    output = generate_group_members_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_local_admins.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


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

@sysinfo_bp.route('/reports/usermgmt/SIMATIC/', methods=['GET'])
@login_required
def local_SIMATIC_users_list():
    groups = find_SIMATIC_groups()
    return render_template('sysinfo/group/group_members_list.html', groups=groups,
                           download_membership_url=url_for("sysinfo.local_SIMATIC_users_excel_full"))


@sysinfo_bp.route('/report/usermgmt/SIMATIC/excel/full', methods=['GET'])
@login_required
def local_SIMATIC_users_excel_full():
    groups = find_SIMATIC_groups()
    output = generate_group_members_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_SIMATIC.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


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