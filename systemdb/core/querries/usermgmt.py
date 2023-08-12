from sqlalchemy import and_

from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.core.sids import SID_BUILTIN_REMOTE_DESKTOP_USERS
from systemdb.core.models.sysinfo import Group
from systemdb.core.models.sysinfo import Host
from systemdb.core.models.activedirectory import ADGroup


def get_direct_domainuser_assignments() -> list[tuple]:
    result = []
    groups = Group.query.all()
    for g in groups:
        for m in g.Members:
            if (m.AccountType == "512") and (str(m.Domain).lower() !=  str(g.Host).lower()):
                result.append((g.Host, g.Name, m.Caption))

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
    groups = Group.query.filter(Group.SID == "S-1-5-32-544").all()
    host_ids = []
    for g in groups:
        for m in g.Members:
            if m.SID.endswith("-512"):
                host_ids.append(g.Host_id)
    return Host.query.filter(Host.id.in_(host_ids)).all()


def find_local_admins() -> list[Group]:
    return Group.query.filter(Group.SID == SID_LOCAL_ADMIN_GROUP).all()


def find_rdp_groups() -> list[Group]:
    return Group.query.filter(Group.SID == SID_BUILTIN_REMOTE_DESKTOP_USERS).all()


def find_SIMATIC_groups() -> list[Group]:
    return Group.query.filter(Group.Name.ilike("%SIMATIC%")).all()


def find_domain_admin_groups() -> list[ADGroup]:
    return ADGroup.query.filter(ADGroup.SID.ilike("%-512")).all()


def find_domain_admin_groups_by_domain_id(domain_id: int) -> list[ADGroup]:
    return ADGroup.query.filter(and_(ADGroup.SID.ilike("%-512"), ADGroup.Domain_id == int(domain_id))).all()

