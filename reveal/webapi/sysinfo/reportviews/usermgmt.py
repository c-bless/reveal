from http import HTTPStatus

from reveal.webapi.sysinfo.reportviews import report_bp
from reveal.webapi.extentions import auth
from reveal.webapi.tags import T_REPORT_SYSINFO
from reveal.webapi.tags import T_GENERAL_HARDENING
from reveal.webapi.tags import T_USERMGMT

from reveal.core.querries.usermgmt import get_direct_domainuser_assignments
from reveal.webapi.sysinfo.schemas.responses.usermgmt import UserGroupAssignment
from reveal.webapi.sysinfo.schemas.responses.hosts import HostSchema
from reveal.core.querries.usermgmt import find_hosts_where_domadm_is_localadmin
from reveal.core.querries.usermgmt import find_hosts_by_autologon_admin

from reveal.webapi.sysinfo.schemas.responses.usermgmt import GroupMembershipSchema
from reveal.core.querries.usermgmt import find_group_local_admins
from reveal.core.querries.usermgmt import find_rdp_groups
from reveal.core.querries.usermgmt import find_PerformanceMonitorUser_groups
from reveal.core.querries.usermgmt import find_DCOM_user_groups
from reveal.core.querries.usermgmt import find_SIMATIC_groups

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
    groups = find_group_local_admins()
    for g in groups:
        membership = GroupMembershipSchema()
        membership.Host = g.Host
        membership.Group = g
        membership.Members = g.Members
        results.append(membership)
    return results



#####################################################################################
# Performance Monitor Users
#####################################################################################
@report_bp.get("/usermgmt/members/perf-monitor-user/")
@report_bp.auth_required(auth)
@report_bp.doc( description='Returns a list of memberships for the "Performance Monitor Users" group for all hosts.',
                summary='Find all memberships of the "Performance Monitor Users" group for all hosts.',
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=GroupMembershipSchema(many=True))
def report_members_performance_monitor_users():
    results = []
    groups = find_PerformanceMonitorUser_groups()
    for g in groups:
        membership = GroupMembershipSchema()
        membership.Host = g.Host
        membership.Group = g
        membership.Members = g.Members
        results.append(membership)
    return results



#####################################################################################
# DCOM Users
#####################################################################################
@report_bp.get("/usermgmt/members/DCOM/")
@report_bp.auth_required(auth)
@report_bp.doc( description='Returns a list of memberships for the "Distributed COM Users" group for all hosts.',
                summary='Find all memberships of the "Distributed COM Users" group for all hosts.',
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=GroupMembershipSchema(many=True))
def report_members_dcom():
    results = []
    groups = find_DCOM_user_groups()
    for g in groups:
        membership = GroupMembershipSchema()
        membership.Host = g.Host
        membership.Group = g
        membership.Members = g.Members
        results.append(membership)
    return results



#####################################################################################
# SIMATIC Users
#####################################################################################
@report_bp.get("/usermgmt/members/SIMATIC/")
@report_bp.auth_required(auth)
@report_bp.doc( description='Returns a list of memberships for the "SIMATIC*" groups for all hosts.',
                summary='Find all memberships of the "SIMATIC*" groups for all hosts.',
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_USERMGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=GroupMembershipSchema(many=True))
def report_members_simatic():
    results = []
    groups = find_SIMATIC_groups()
    for g in groups:
        membership = GroupMembershipSchema()
        membership.Host = g.Host
        membership.Group = g
        membership.Members = g.Members
        results.append(membership)
    return results