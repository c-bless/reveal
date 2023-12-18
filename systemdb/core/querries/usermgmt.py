from sqlalchemy import and_

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.core.sids import SID_BUILTIN_REMOTE_DESKTOP_USERS
from systemdb.core.sids import SID_BUILTIN_REMOTE_MANAGEMENT_USERS
from systemdb.core.sids import SID_BUILTIN_DCOM_USERS
from systemdb.core.sids import SID_BUILTIN_PERFORMANCE_MONITOR_USERS

from systemdb.core.models.sysinfo import Group
from systemdb.core.models.sysinfo import GroupMember
from systemdb.core.models.sysinfo import Host
from systemdb.core.models.sysinfo import User


def get_direct_domainuser_assignments(host_filter=[]) -> list[tuple]:
    """
    Returns a list of tuples with Host, Group and GroupMember objects.

    :param host_filter: list of filter to apply to Host obeject in SQL query
    :return: list of tuple (Host object, Group object, GroupMember object)
    """
    result = []
    groups = Group.query.join(Host).filter(and_(*host_filter)).all()
    for g in groups:
        for m in g.Members:
            if (m.AccountType == "512") and (str(m.Domain).lower() !=  str(g.Host).lower()):
                result.append((g.Host, g, m))

    return result


def find_hosts_by_local_user(username = "", host_filter=[]) -> list[Host]:
    user_filter = []
    user_filter.append(User.LocalAccount == True)
    user_filter.append(User.Disabled == False)
    if len(user_filter) > 0:
        user_filter.append(User.Name.ilike("%" + username + "%"))
    users = User.query.filter(and_(*user_filter)).join(Host).filter(and_(*host_filter)).all()
    hosts = [u.Host for u in users]
    hosts_unique = []
    host_ids = []
    for h in hosts:
        if h.id not in host_ids:
            host_ids.append(h.id)
            hosts_unique.append(h)
    return hosts


def get_autologon_admin(host_filter=[]):
    result = []
    host_filter.append(Host.AutoAdminLogon == True)
    autologon_hosts = Host.query.filter(and_(*host_filter)).all()
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


def find_group_local_admins(user_filter=[], host_filter=[])  -> list[Group]:
    group_filter = [Group.SID == SID_LOCAL_ADMIN_GROUP]
    return find_group_by_filter(group_filter=group_filter, user_filter=user_filter, host_filter=host_filter)


def find_group_by_filter(group_filter=[], user_filter=[], host_filter=[]) -> list[Group]:
    groups = Group.query.filter(and_(*group_filter)). \
        join(GroupMember).filter(and_(*user_filter)). \
        join(Host).filter(and_(*host_filter)).all()
    return groups


def find_rdp_groups(host_filter=[]) -> list[Group]:
    group_filter = [Group.SID == SID_BUILTIN_REMOTE_DESKTOP_USERS]
    return find_group_by_filter(group_filter=group_filter, host_filter=host_filter)


def find_SIMATIC_groups(host_filter=[])-> list[Group]:
    group_filter = [Group.Name.ilike("%SIMATIC%")]
    return find_group_by_filter(group_filter=group_filter, host_filter=host_filter)


def find_RemoteMgmtUser_groups(host_filter=[])-> list[Group]:
    group_filter = [Group.SID == SID_BUILTIN_REMOTE_MANAGEMENT_USERS]
    return find_group_by_filter(group_filter=group_filter, host_filter=host_filter)


def find_DCOM_user_groups(host_filter=[]) -> list[Group]:
    group_filter = [Group.SID == SID_BUILTIN_DCOM_USERS]
    return find_group_by_filter(group_filter=group_filter, host_filter=host_filter)


def find_PerformanceMonitorUser_groups(host_filter=[]) -> list[Group]:
    group_filter = [Group.SID == SID_BUILTIN_PERFORMANCE_MONITOR_USERS]
    return find_group_by_filter(group_filter=group_filter, host_filter=host_filter)


def find_groups_by_user_sid(sid) -> list[Group]:
    groups = Group.query.filter().\
        join(GroupMember).filter(GroupMember.SID == sid).all()
    return groups


def find_local_admins_group_member(user_filter=[], host_filter=[]) -> list[GroupMember]:
    members = GroupMember.query.filter(and_(*user_filter)).\
        join(Group).filter(Group.SID == SID_LOCAL_ADMIN_GROUP).\
        join(Host).filter(and_(*host_filter)).all()
    return members
