from flask import render_template
from flask import request
from flask import Response
from sqlalchemy import and_
from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp

from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import Group
from reveal.core.models.sysinfo import GroupMember
from reveal.core.models.sysinfo import User
from reveal.core.querries.usermgmt import find_groups_by_user_sid
from reveal.core.export.excel.usermgmt import generate_localuser_excel
from reveal.webapp.sysinfo.forms.users import LocalUserSearchForm

from reveal.webapp.sysinfo.forms.groups import LocalGroupMemberSearchForm
from reveal.core.querries.usermgmt import find_group_local_admins
from reveal.core.export.excel.usermgmt import generate_group_members_excel


@sysinfo_bp.route('/groups/<int:id>', methods=['GET'])
@login_required
def group_detail(id):
    group = Group.query.get_or_404(id)
    host = Host.query.get_or_404(group.Host_id)
    return render_template("sysinfo/group/group_details.html", group=group, host=host)


@sysinfo_bp.route('/users/<int:id>', methods=['GET'])
@login_required
def user_detail(id):
    user = User.query.get_or_404(id)
    host = Host.query.get_or_404(user.Host_id)
    groups = find_groups_by_user_sid(sid=user.SID)
    return render_template("sysinfo/user/user_details.html", user=user, host=host, groups=groups)


@sysinfo_bp.route('/users/search', methods=['GET', 'POST'])
@login_required
def user_search_list():
    form = LocalUserSearchForm()

    if request.method == 'POST':
        user_filter = []
        host_filter = []
        users = []
        if form.validate_on_submit():
            name = form.Name.data
            fullName = form.FullName.data
            try:
                accountType = str(form.AccountType.data)
            except:
                accountType = str(512)
            sid = form.SID.data
            description = form.Description.data
            host = form.Host.data
            systemgroup = form.SystemGroup.data

            invertName = form.InvertName.data
            invertFullName = form.InvertFullName.data
            invertDescription = form.InvertDescription.data
            invertSID = form.InvertSID.data
            invertHost = form.InvertHost.data
            invertAccountType = form.InvertAccountType.data
            invertSystemgroup = form.InvertSystemGroup.data

            lockout = form.Lockout.data
            passwordRequired = form.PasswordRequired.data
            passwordChanged = form.PasswordChanged.data
            useLockout = form.UseLockout.data
            usePasswordRequired= form.UsePasswordRequired.data
            usePasswordChanged= form.UsePasswordChanged.data
            useDescriptionNotEmpty= form.UseDescriptionNotEmpty.data
            descriptionNotEmpty=form.DescriptionNotEmpty.data

            if len(name) > 0:
                if not invertName:
                    user_filter.append(User.Name.ilike("%"+name+"%"))
                else:
                    user_filter.append(User.Name.notilike("%"+name+"%"))
            if len(fullName) > 0:
                if not invertFullName:
                    user_filter.append(User.FullName.ilike("%"+fullName+"%"))
                else:
                    user_filter.append(User.FullName.notilike("%"+fullName+"%"))
            if len(accountType):
                if not invertAccountType:
                    user_filter.append(User.AccountType == accountType)
                else:
                    user_filter.append(User.AccountType != accountType)
            if len(sid) > 0:
                if not invertSID:
                    user_filter.append(User.SID.ilike("%"+sid+"%"))
                else:
                    user_filter.append(User.SID.notilike("%"+sid+"%"))
            if len(description) > 0:
                if not invertDescription:
                    user_filter.append(User.Description.ilike("%" + description + "%"))
                else:
                    user_filter.append(User.Description.notilike("%" + description + "%"))
            if useLockout:
                user_filter.append(User.Lockout == lockout)
            if usePasswordChanged:
                user_filter.append(User.PasswordChanged == passwordChanged)
            if usePasswordRequired:
                user_filter.append(User.PasswordRequired == passwordRequired)
            if useDescriptionNotEmpty:
                if descriptionNotEmpty:
                    user_filter.append(User.Description != None)
                else:
                    user_filter.append(User.Description == None)

            if len(host) > 0:
                if not invertHost:
                    host_filter.append(Host.Hostname.ilike("%"+host+"%"))
                else:
                    host_filter.append(Host.Hostname.notilike("%"+host+"%"))
            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    host_filter.append(Host.SystemGroup.ilike("%"+systemgroup+"%"))
                else:
                    host_filter.append(Host.SystemGroup.notilike("%"+systemgroup+"%"))

            users = User.query.filter(and_(*user_filter)).join(Host).filter(and_(*host_filter)).all()

            if 'excel' in request.form:
                output = generate_localuser_excel(users=users)
                return Response(output, mimetype="text/xslx",
                                headers={"Content-disposition": "attachment; filename=local-users.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    else:
        users = []

    return render_template('sysinfo/user/user_search_list.html', form=form, users=users)




#####################################################################################
# Get local admins
#####################################################################################
@sysinfo_bp.route('/groups/localadmins/', methods=['GET','POST'])
@login_required
def localadmin_search_list():
    form = LocalGroupMemberSearchForm()

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
        if len(hostname) > 0 :
            if invertHostname == False:
                host_filter.append(Host.Hostname.ilike("%"+hostname+"%"))
            else:
                host_filter.append(Host.Hostname.notilike("%"+hostname+"%"))
        if len(domain) > 0 :
            if invertDomain == False:
                user_filter.append(GroupMember.Domain.ilike("%"+domain+"%"))
            else:
                user_filter.append(GroupMember.Domain.notilike("%"+domain+"%"))
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
        groups = find_group_local_admins(user_filter=user_filter, host_filter=host_filter)

    return render_template('sysinfo/group/group_members_list.html',form=form, groups=groups,
                           report_name="Local Admins")

