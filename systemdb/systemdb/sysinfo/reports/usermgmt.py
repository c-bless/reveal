from flask import render_template, Response, url_for
from sqlalchemy import and_
from .. import sysinfo_bp
from ..export_func import generate_userassignment_excel
from ..vars import SID_LOCAL_ADMIN_GROUP

from ...models.sysinfo import Host, Group, GroupMember
from . import ReportInfo

####################################################################
# Hosts with Domain Admins in local admin group
####################################################################
def get_direct_domainuser_assignments():
    result = []
    groups = Group.query.all()
    for g in groups:
        for m in g.Members:
            if (m.AccountType == "512") and (str(m.Domain).lower() !=  str(g.Host).lower()):
                result.append((g.Host, g.Name, m.Caption))

    return result


@sysinfo_bp.route('/reports/usermgmt/assigment/', methods=['GET'])
def usermgmt_assignment_list():
    members = get_direct_domainuser_assignments()
    return render_template('userassignment_list.html',members=members)


@sysinfo_bp.route('/report/usermgmt/assignment/excel/full', methods=['GET'])
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
            description='Report all hosts which have domain users directly assigned instead of centrally managed domain groups.',
            views=[("view", url_for("sysinfo.usermgmt_assignment_list"))]
        )