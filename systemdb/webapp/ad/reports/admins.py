from flask import render_template, Response, url_for, request
from flask_login import login_required
from sqlalchemy import and_

from systemdb.webapp.ad import ad_bp
from systemdb.core.reports import ReportInfo
from systemdb.core.export.excel.usermgmt import generate_group_members_excel
from systemdb.core.querries.usermgmt import find_domain_admin_groups

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP


####################################################################
# Members in local SIMATIC groups
####################################################################

@ad_bp.route('/reports/members/domainadmins/', methods=['GET'])
@login_required
def members_domain_admin_group():
    groups = find_domain_admin_groups()
    return render_template('report_groupmembers_list.html', groups=groups, report_name= 'GroupMembers "Domain Admins"')


@ad_bp.route('/reports/members/domainadmins/excel/full', methods=['GET'])
@login_required
def members_domain_admin_group_excel_full():
    groups = find_domain_admin_groups()
    output = generate_group_members_excel(groups)

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
            views=[("view", url_for("ad.members_domain_admin_group"))]
        )
