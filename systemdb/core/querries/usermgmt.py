from sqlalchemy import and_

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.core.sids import SID_BUILTIN_REMOTE_DESKTOP_USERS
from systemdb.core.sids import SID_BUILTIN_REMOTE_MANAGEMENT_USERS
from systemdb.core.sids import SID_BUILTIN_DCOM_USERS
from systemdb.core.sids import SID_BUILTIN_PERFORMANCE_MONITOR_USERS

from systemdb.core.models.sysinfo import Group
from systemdb.core.models.sysinfo import GroupMember
from systemdb.core.models.sysinfo import Host



def get_direct_domainuser_assignments() -> list[tuple]:
    result = []
    groups = Group.query.all()
    for g in groups:
        for m in g.Members:
            if (m.AccountType == "512") and (str(m.Domain).lower() !=  str(g.Host).lower()):
                result.append((g.Host, g.Name, m.Caption))

    return result


def get_autologon_admin(host_filter=[]):
    result = []
    host_filter.append(Host.AutoAdminLogon == True)
    autologon_hosts = Host.query.filter(*host_filter).all()
    for h in autologon_hosts:
        defaultUser = h.DefaultUserName
        defaultDomain = h.DefaultDomain
        admins = Group.query.filter(and_(Group.SID == SID_LOCAL_ADMIN_GROUP, Group.Host_id == h.id)).first()
        for m in admins.Members:
            if defaultDomain == m.Domain and defaultUser == m.Name:
                result.append(h)
    return result


def find_hosts_by_autologon_admin() -> list[Host]:
    result = []
    autologon_hosts = Host.query.filter(Host.AutoAdminLogon == 1).all()
    for h in autologon_hosts:
        defaultUser = h.DefaultUserName
        defaultDomain = h.DefaultDomain
        admins = Group.query.filter(and_(Group.SID == SID_LOCAL_ADMIN_GROUP, Group.Host_id == h.id)).first()
        for m in admins.Members:
            if defaultDomain == m.Domain and defaultUser == m.Name:
                result.append(h)
    return result


def find_hosts_where_domadm_is_localadmin() -> list[Host]:
    groups = Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).all()
    host_ids = []
    for g in groups:
        for m in g.Members:
            if m.SID.endswith("-512"):
                host_ids.append(g.Host_id)
    return Host.query.filter(Host.id.in_(host_ids)).all()


def find_hosts_where_domadm_is_localadmin_with_host_filter(host_filter) -> list[Host]:
    groups = Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).all()
    host_ids = []
    for g in groups:
        for m in g.Members:
            if m.SID.endswith("-512"):
                host_ids.append(g.Host_id)
    host_filter.append(Host.id.in_(host_ids))
    return Host.query.filter(*host_filter).all()


def find_groups_where_domadm_is_localadmin() -> list[Group]:
    groups = Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).\
        join(GroupMember).filter(GroupMember.SID.endswith("-512")).all()
    return groups


def find_groups_where_domadm_is_localadmin_with_host_filter(host_filter) -> list[Group]:
    groups = Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).\
        join(GroupMember).filter(GroupMember.SID.endswith("-512")).join(Host).filter(*host_filter).all()
    return groups


def find_local_admins() -> list[Group]:
    return Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).all()


def find_rdp_groups() -> list[Group]:
    return Group.query.filter(Group.SID == SID_BUILTIN_REMOTE_DESKTOP_USERS).all()


def find_SIMATIC_groups() -> list[Group]:
    return Group.query.filter(Group.Name.ilike("%SIMATIC%")).all()


def find_RemoteMgmtUser_groups() -> list[Group]:
    return Group.query.filter(Group.SID == SID_BUILTIN_REMOTE_MANAGEMENT_USERS).all()


def find_DCOM_user_groups() -> list[Group]:
    return Group.query.filter(Group.SID == SID_BUILTIN_DCOM_USERS).all()


def find_PerformanceMonitorUser_groups() -> list[Group]:
    return Group.query.filter(Group.SID == SID_BUILTIN_PERFORMANCE_MONITOR_USERS).all()


def find_groups_by_user_sid(sid) -> list[Group]:
    groups = Group.query.filter().\
        join(GroupMember).filter(GroupMember.SID == sid).all()
    return groups
