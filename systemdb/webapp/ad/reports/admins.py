from flask import render_template, Response, url_for, request
from flask_login import login_required

from systemdb.webapp.ad import ad_bp
from systemdb.core.reports import ReportInfo
from systemdb.core.export.excel.ad_groupmembers import generate_ad_groupmembers_excel
from systemdb.core.querries.ad import find_domain_admin_groups
from systemdb.core.querries.ad import find_enterprise_admin_groups
from systemdb.core.querries.ad import find_schema_admin_groups

####################################################################
# Members in Domain Admins groups
####################################################################

@ad_bp.route('/reports/members/domainadmins/', methods=['GET'])
@login_required
def groupmembers_domain_admins():
    groups = find_domain_admin_groups()
    return render_template('ad/reports/groupmembers_list.html', groups=groups,
                           download_url= url_for("ad.groupmembers_domain_admins_excel_full"),
                           report_name= 'GroupMembers "Domain Admins"')


@ad_bp.route('/reports/members/domainadmins/excel/full', methods=['GET'])
@login_required
def groupmembers_domain_admins_excel_full():
    groups = find_domain_admin_groups()
    output = generate_ad_groupmembers_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_domain_admins.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


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
# Members in Enterprise Admins groups
####################################################################

@ad_bp.route('/reports/members/enterpriseadmins/', methods=['GET'])
@login_required
def groupmembers_enterprise_admins():
    groups = find_enterprise_admin_groups()
    return render_template('ad/reports/groupmembers_list.html', groups=groups,
                           download_url= url_for("ad.groupmembers_enterprise_admins_excel_full"),
                           report_name= 'GroupMembers "Enterprise Admins"')


@ad_bp.route('/reports/members/enterpriseadmins/excel/full', methods=['GET'])
@login_required
def groupmembers_enterprise_admins_excel_full():
    groups = find_enterprise_admin_groups()
    output = generate_ad_groupmembers_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_enterprise_admins.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


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

@ad_bp.route('/reports/members/schemaadmins/', methods=['GET'])
@login_required
def groupmembers_schema_admins():
    groups = find_schema_admin_groups()
    return render_template('ad/reports/groupmembers_list.html', groups=groups,
                           download_url= url_for("ad.groupmembers_schema_admins_excel_full"),
                           report_name= 'GroupMembers "Schema Admins"')


@ad_bp.route('/reports/members/schemaadmins/excel/full', methods=['GET'])
@login_required
def groupmembers_schema_admins_excel_full():
    groups = find_schema_admin_groups()
    output = generate_ad_groupmembers_excel(groups)

    return Response(output, mimetype="text/xlsx",
                 headers={"Content-disposition": "attachment; filename=groupmembers_schema_admins.xlsx",
                              "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" })


class ReportSchemaAdminGroups(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name='List members of "Schema Admins" group',
            category="User Management",
            tags=["User Management", "Schema Admins", "Schema Administrators", "GroupMembers"],
            description='Report all members of of "Schema Admin" group.',
            views=[("view", url_for("ad.groupmembers_schema_admins"))]
        )

