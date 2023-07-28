from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.core.models.sysinfo import Host, Group, GroupMember, User
from systemdb.core.querries.usermgmt import get_direct_domainuser_assignments
from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.webapp.sysinfo.export_func import generate_userassignment_excel, generate_hosts_excel
from systemdb.webapp.sysinfo.reports import ReportInfo
from systemdb.webapp.sysinfo.forms.hosts import HostByLocalUserSearchForm
from systemdb.webapp.sysinfo.forms.groups import LocalAdminSearchForm


####################################################################
# Hosts with Domain Admins in local admin group
####################################################################



@sysinfo_bp.route('/reports/usermgmt/assigment/', methods=['GET'])
@login_required
def usermgmt_assignment_list():
    members = get_direct_domainuser_assignments()
    return render_template('userassignment_list.html',members=members)


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
            description='Report all hosts which have views users directly assigned instead of centrally managed views groups.',
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
        user_filter = form.Name.data
        users = User.query.filter(and_(
            User.LocalAccount == True,
            User.Name.ilike("%"+user_filter+"%"),
            User.Disabled == False
        )).all()
        hosts = [u.Host for u in users]
        if 'full' in request.form:
            output = generate_hosts_excel(hosts)
            return Response(output, mimetype="text/xslx",
                            headers={"Content-disposition": "attachment; filename=hosts-by-localuser.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    else:
        users = User.query.filter(and_(
            User.LocalAccount == True,
            User.Disabled == False
        )).all()
        hosts = [u.Host for u in users]

    return render_template('host_search_by_user_list.html',form=form, hosts=hosts)



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

    return render_template('local_admin_list.html',form=form, members=members)


class ReportHostsByLocaluser(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="Local Admin",
            category="User Management",
            tags=["User Management", "Local Accounts"],
            description='Report members of local administrators group.',
            views=[("view", url_for("sysinfo.report_localadmin_list"))]
        )
