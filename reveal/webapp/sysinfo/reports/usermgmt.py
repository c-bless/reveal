from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from reveal.core.sids import SID_LOCAL_ADMIN_GROUP
from reveal.core.models.sysinfo import Host, Group, GroupMember, User
from reveal.core.querries.usermgmt import get_direct_domainuser_assignments
from reveal.core.querries.usermgmt import find_group_local_admins
from reveal.core.querries.usermgmt import find_rdp_groups
from reveal.core.querries.usermgmt import find_SIMATIC_groups
from reveal.core.querries.usermgmt import find_RemoteMgmtUser_groups
from reveal.core.querries.usermgmt import find_DCOM_user_groups
from reveal.core.querries.usermgmt import find_PerformanceMonitorUser_groups
from reveal.core.querries.usermgmt import find_hosts_by_local_user
from reveal.core.querries.usermgmt import find_local_admins_group_member


from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.export.excel.usermgmt import generate_userassignment_excel
from reveal.core.export.excel.usermgmt import generate_group_members_excel
from reveal.core.export.excel.hosts import generate_hosts_excel
from reveal.core.reports import ReportInfo
from reveal.webapp.sysinfo.forms.report.UserMgmtReports import HostByLocalUserSearchForm
from reveal.webapp.sysinfo.forms.report.UserMgmtReports import LocalAdminSearchForm
from reveal.webapp.sysinfo.forms.report.UserMgmtReports import DirectAssignmentReportForm
from reveal.webapp.sysinfo.forms.report.UserMgmtReports import LocalAdminSearchForm
from reveal.webapp.sysinfo.forms.report.UserMgmtReports import LocalGroupMemberSearchForm

from reveal.core.export.word.util import get_group_report_templates
from reveal.core.export.word.util import get_group_report_directory
from reveal.core.export.word.util import generate_group_report_docx


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
            label = form.Label.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

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
            if len(label) > 0:
                if not invertLabel:
                    host_filter.append(Host.Label.ilike("%"+label+"%"))
                else:
                    host_filter.append(Host.Label.notilike("%"+label+"%"))

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
            label = form.Label.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data
            invertLabel = form.InvertLabel.data

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
            if len(label) > 0:
                if not invertLabel:
                    host_filter.append(Host.Label.ilike("%"+label+"%"))
                else:
                    host_filter.append(Host.Label.notilike("%"+label+"%"))

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

    templates = get_group_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        username = form.Username.data
        domain = form.Domain.data
        hostname = form.Hostname.data
        invertUsername = form.InvertUsername.data
        invertDomain = form.InvertDomain.data
        invertHostname = form.InvertHostname.data
        selectedTemplate = form.TemplateFile.data

        systemgroup = form.SystemGroup.data
        location = form.Location.data
        label = form.Label.data

        invertSystemgroup = form.InvertSystemGroup.data
        invertLocation = form.InvertLocation.data
        invertLabel = form.InvertLabel.data

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
        if len(label) > 0:
            if not invertLabel:
                host_filter.append(Host.Label.ilike("%"+label+"%"))
            else:
                host_filter.append(Host.Label.notilike("%"+label+"%"))
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
        if 'word' in request.form:
            if selectedTemplate in templates:
                template_dir = get_group_report_directory()
                report = ReportLocalAdmins()
                output = generate_group_report_docx(f"{template_dir}/{selectedTemplate}", report, groups=groups)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
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
    form = LocalGroupMemberSearchForm()

    host_filter = []

    templates = get_group_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        systemgroup = form.SystemGroup.data
        location = form.Location.data
        selectedTemplate = form.TemplateFile.data
        label = form.Label.data

        invertSystemgroup = form.InvertSystemGroup.data
        invertLocation = form.InvertLocation.data
        invertLabel = form.InvertLabel.data

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
        if len(label) > 0:
            if not invertLabel:
                host_filter.append(Host.Label.ilike("%"+label+"%"))
            else:
                host_filter.append(Host.Label.notilike("%"+label+"%"))
        groups = find_SIMATIC_groups(host_filter=host_filter)

        if 'excel' in request.form:
            output = generate_group_members_excel(groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_SIMATIC.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        if 'word' in request.form:
            if selectedTemplate in templates:
                template_dir = get_group_report_directory()
                report = ReportSIMATICUsers()
                output = generate_group_report_docx(f"{template_dir}/{selectedTemplate}", report, groups=groups)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
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

@sysinfo_bp.route('/reports/usermgmt/RDP/', methods=['GET', 'POST'])
@login_required
def local_rdp_users_list():
    form = LocalGroupMemberSearchForm()

    host_filter = []

    templates = get_group_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        systemgroup = form.SystemGroup.data
        location = form.Location.data
        selectedTemplate = form.TemplateFile.data
        label = form.Label.data

        invertSystemgroup = form.InvertSystemGroup.data
        invertLocation = form.InvertLocation.data
        invertLabel = form.InvertLabel.data

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
        if len(label) > 0:
            if not invertLabel:
                host_filter.append(Host.Label.ilike("%"+label+"%"))
            else:
                host_filter.append(Host.Label.notilike("%"+label+"%"))
        groups = find_rdp_groups(host_filter=host_filter)

        if 'excel' in request.form:
            output = generate_group_members_excel(groups)

            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_RDP.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        if 'word' in request.form:
            if selectedTemplate in templates:
                template_dir = get_group_report_directory()
                report = ReportRDPUsers()
                output = generate_group_report_docx(f"{template_dir}/{selectedTemplate}", report, groups=groups)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
    else:
        groups = find_rdp_groups(host_filter=host_filter)

    return render_template('sysinfo/reports/group_members_list.html', groups=groups, form=form,
                           report_name='List members of local "Remote Desktop Users" groups')



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

@sysinfo_bp.route('/reports/usermgmt/remotemgmtuser/', methods=['GET', 'POST'])
@login_required
def local_remote_mgmt_users_list():
    form = LocalGroupMemberSearchForm()

    host_filter = []

    templates = get_group_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        systemgroup = form.SystemGroup.data
        location = form.Location.data
        selectedTemplate = form.TemplateFile.data
        label = form.Label.data

        invertSystemgroup = form.InvertSystemGroup.data
        invertLocation = form.InvertLocation.data
        invertLabel = form.InvertLabel.data

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
        if len(label) > 0:
            if not invertLabel:
                host_filter.append(Host.Label.ilike("%"+label+"%"))
            else:
                host_filter.append(Host.Label.notilike("%"+label+"%"))
        groups = find_RemoteMgmtUser_groups(host_filter=host_filter)

        if 'excel' in request.form:
            output = generate_group_members_excel(groups)

            return Response(output, mimetype="text/xlsx",
                         headers={"Content-disposition": "attachment; filename=groupmembers_remote_mgmt_users.xlsx",
                                      "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })
        if 'word' in request.form:
            if selectedTemplate in templates:
                template_dir = get_group_report_directory()
                report = ReportRemoteManagementUsers()
                output = generate_group_report_docx(f"{template_dir}/{selectedTemplate}", report, groups=groups)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
    else:
        groups = find_RemoteMgmtUser_groups(host_filter=host_filter)

    return render_template('sysinfo/reports/group_members_list.html', groups=groups, form=form,
                           report_name='List members of "Remote Management Users" groups')


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

@sysinfo_bp.route('/reports/usermgmt/dcom/', methods=['GET', 'POST'])
@login_required
def local_dcom_users_list():
    form = LocalGroupMemberSearchForm()

    host_filter = []

    templates = get_group_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        systemgroup = form.SystemGroup.data
        location = form.Location.data
        selectedTemplate = form.TemplateFile.data
        label = form.Label.data

        invertSystemgroup = form.InvertSystemGroup.data
        invertLocation = form.InvertLocation.data
        invertLabel = form.InvertLabel.data

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
        if len(label) > 0:
            if not invertLabel:
                host_filter.append(Host.Label.ilike("%"+label+"%"))
            else:
                host_filter.append(Host.Label.notilike("%"+label+"%"))
        groups = find_DCOM_user_groups(host_filter=host_filter)

        if 'excel' in request.form:
            output = generate_group_members_excel(groups)

            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_DCOM_users.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        if 'word' in request.form:
            if selectedTemplate in templates:
                template_dir = get_group_report_directory()
                report = ReportDCOMUsers()
                output = generate_group_report_docx(f"{template_dir}/{selectedTemplate}", report, groups=groups)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
    else:
        groups = find_DCOM_user_groups(host_filter=host_filter)

    return render_template('sysinfo/reports/group_members_list.html', groups=groups, form=form,
                           report_name='List members of "Distributed COM Users" groups')

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
@sysinfo_bp.route('/reports/usermgmt/performancemonitor/', methods=['GET', 'POST'])
@login_required
def local_performance_monitor_users_list():
    form = LocalGroupMemberSearchForm()

    host_filter = []

    templates = get_group_report_templates()
    form.TemplateFile.choices = [(template, template) for template in templates]

    if request.method == 'POST':
        systemgroup = form.SystemGroup.data
        location = form.Location.data
        selectedTemplate = form.TemplateFile.data
        label = form.Label.data

        invertSystemgroup = form.InvertSystemGroup.data
        invertLocation = form.InvertLocation.data
        invertLabel = form.InvertLabel.data

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
        if len(label) > 0:
            if not invertLabel:
                host_filter.append(Host.Label.ilike("%"+label+"%"))
            else:
                host_filter.append(Host.Label.notilike("%"+label+"%"))
        groups = find_PerformanceMonitorUser_groups(host_filter=host_filter)

        if 'excel' in request.form:
            output = generate_group_members_excel(groups)

            return Response(output, mimetype="text/xlsx",
                            headers={
                                "Content-disposition": "attachment; filename=groupmembers_PerformanceMonitorUsers.xlsx",
                                "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
        if 'word' in request.form:
            if selectedTemplate in templates:
                template_dir = get_group_report_directory()
                report = ReportPerformanceMonitorUsers()
                output = generate_group_report_docx(f"{template_dir}/{selectedTemplate}", report, groups=groups)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename={0}.docx".format(report.name)})
    else:
        groups = find_PerformanceMonitorUser_groups(host_filter=host_filter)

    return render_template('sysinfo/reports/group_members_list.html', groups=groups, form=form,
                           report_name='List members of "Performance Monitor Users" groups')


class ReportPerformanceMonitorUsers(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Performance Monitor Users" groups',
            category="User Management",
            tags=["User Management", "Performance Monitor Users", "GroupMembers"],
            description='Report all members of "Performance Monitor Users',
            views=[("view", url_for("sysinfo.local_performance_monitor_users_list"))]
        )