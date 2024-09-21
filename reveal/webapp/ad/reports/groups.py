from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.ad import ad_bp
from reveal.core.reports import ReportInfo
from reveal.core.export.excel.ad_groupmembers import generate_ad_groupmembers_excel
from reveal.core.querries.ad import find_domain_admin_groups
from reveal.core.querries.ad import find_enterprise_admin_groups
from reveal.core.querries.ad import find_schema_admin_groups
from reveal.core.querries.ad import find_protected_users
from reveal.webapp.ad.forms.groups import GroupDownload

####################################################################
# Members in Domain Admins groups
####################################################################

@ad_bp.route('/reports/members/domainadmins/', methods=['GET', 'POST'])
@login_required
def groupmembers_domain_admins():
    form = GroupDownload()
    groups = find_domain_admin_groups()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_ad_groupmembers_excel(groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_domain_admins.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/groupmembers_list.html', groups=groups, form=form,
                           report_name= 'GroupMembers "Domain Admins"')


class ReportDomainAdminGroups(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Domain Admins" group',
            category="User Management",
            tags=["User Management", "Domain Admins", "Domain Administrators", "GroupMembers"],
            description='Report all members of of "Domain Admins" group.',
            views=[("view", url_for("ad.groupmembers_domain_admins"))]
        )


####################################################################
# Members in Domain Admins groups
####################################################################

@ad_bp.route('/reports/members/protectedusers/', methods=['GET', 'POST'])
@login_required
def groupmembers_protected_users():
    form = GroupDownload()
    groups = find_protected_users()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_ad_groupmembers_excel(groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_protected_users.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    return render_template('ad/reports/groupmembers_list.html', groups=groups, form=form,
                           report_name= 'GroupMembers "Protected Users"')


class ReportProtectedUsersGroups(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Protected Users" group',
            category="User Management",
            tags=["User Management", "Domain Admins", "Domain Administrators", "GroupMembers"],
            description='Report all members of of "Protected Users" group.',
            views=[("view", url_for("ad.groupmembers_protected_users"))]
        )

####################################################################
# Members in Enterprise Admins groups
####################################################################
@ad_bp.route('/reports/members/enterpriseadmins/', methods=['GET', 'POST'])
@login_required
def groupmembers_enterprise_admins():
    form = GroupDownload()
    groups = find_enterprise_admin_groups()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_ad_groupmembers_excel(groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_enterprise_admins.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    return render_template('ad/reports/groupmembers_list.html', groups=groups, form=form,
                           report_name= 'GroupMembers "Enterprise Admins"')


class ReportEnterpriseAdminGroups(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Enterprise Admins" group',
            category="User Management",
            tags=["User Management", "Enterprise Admins", "Enterprise Administrators", "GroupMembers"],
            description='Report all members of of "Enterprise Admins" group.',
            views=[("view", url_for("ad.groupmembers_enterprise_admins"))]
        )


####################################################################
# Members in Schema Admins groups
####################################################################
@ad_bp.route('/reports/members/schemaadmins/', methods=['GET', 'POST'])
@login_required
def groupmembers_schema_admins():
    form = GroupDownload()
    groups = find_schema_admin_groups()
    if request.method == 'POST' and form.validate_on_submit():
        if 'download' in request.form:
            output = generate_ad_groupmembers_excel(groups)
            return Response(output, mimetype="text/xlsx",
                            headers={"Content-disposition": "attachment; filename=groupmembers_schema_admins.xlsx",
                                     "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
    return render_template('ad/reports/groupmembers_list.html', groups=groups, form=form,
                           report_name= 'GroupMembers "Schema Admins"')


class ReportSchemaAdminGroups(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Schema Admins" group',
            category="User Management",
            tags=["User Management", "Schema Admins", "Schema Administrators", "GroupMembers"],
            description='Report all members of of "Schema Admin" group.',
            views=[("view", url_for("ad.groupmembers_schema_admins"))]
        )