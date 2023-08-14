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

from systemdb.webapi.sysinfo.schemas.responses.usermgmt import GroupMembershipSchema
from systemdb.core.querries.usermgmt import find_local_admins
from systemdb.core.querries.usermgmt import find_rdp_groups

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
@report_bp.get("/usermgmt/admins/domainadmins/")
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
@report_bp.get("/usermgmt/admins/autologon/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns a list of hosts that use autologon with an administrative account.",
                summary="Find all hosts configured for using autologon with an administrative account.",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=HostSchema(many=True))
def report_hosts_with_autologon_admin():
    return find_hosts_by_autologon_admin()


#####################################################################################
# RDP users
#####################################################################################
@report_bp.get("/usermgmt/members/rdp/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns a list of RDP group memberships for all hosts.",
                summary="Find all RDP group memberships for all hosts.",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=GroupMembershipSchema(many=True))
def report_members_rdp():
    results = []
    groups = find_rdp_groups()
    for g in groups:
        membership = GroupMembershipSchema()
        membership.Host = g.Host
        membership.Group = g
        membership.Members = g.Members
        results.append(membership)
    return results


#####################################################################################
# Local Admin users
#####################################################################################
@report_bp.get("/usermgmt/members/admins/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns a list of memberships for the local administrators group for all hosts.",
                summary="Find all memberships for the local administrators group for all hosts.",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=GroupMembershipSchema(many=True))
def report_members_local_admins():
    results = []
    groups = find_local_admins()
    for g in groups:
        membership = GroupMembershipSchema()
        membership.Host = g.Host
        membership.Group = g
        membership.Members = g.Members
        results.append(membership)
    return results


