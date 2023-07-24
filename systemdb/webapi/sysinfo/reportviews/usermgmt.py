from http import HTTPStatus

from systemdb.webapi.sysinfo.reportviews import report_bp
from systemdb.webapi.extentions import auth
from systemdb.webapi.tags import T_REPORT_SYSINFO
from systemdb.webapi.tags import T_GENERAL_HARDENING
from systemdb.webapi.tags import T_USERMGMT

from systemdb.core.querries.usermgmt import get_direct_domainuser_assignments
from systemdb.webapi.sysinfo.schemas.responses.usermgmt import UserGroupAssignment
from systemdb.webapi.sysinfo.schemas.responses.hosts import HostSchema
from systemdb.core.querries.usermgmt import find_hosts_where_domadm_is_localadmin
from systemdb.core.querries.usermgmt import find_hosts_by_autologon_admin

@report_bp.get("/usermgmt/assignments/domainusers/")
@report_bp.auth_required(auth)
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=UserGroupAssignment(many=True))
@report_bp.doc(description="Return a list of domain users that area directly assigned to a local group.",
        summary="Find domain users that area directly assigned to a local group",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
def get_direct_domainuser_assingments():
    members = get_direct_domainuser_assignments()
    return members


#####################################################################################
# Hosts with "Domain Admins" in local admin group
#####################################################################################
@report_bp.get("/domainadmins/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns the hosts with 'Domain Admins' in local admin group.",
                summary="Find all hosts with 'Domain Admins' in local admin group.",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=HostSchema(many=True))
def report_domadmin_is_local_admin():
    return find_hosts_where_domadm_is_localadmin()


#####################################################################################
# Autologin as admin user
#####################################################################################
@report_bp.get("/autologon-admin/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns a list of hosts that use autologon with an administrative account.",
                summary="Find all hosts configured for using autologon with an administrative account.",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=HostSchema(many=True))
def report_hosts_with_autologon_admin():
    return find_hosts_by_autologon_admin()


