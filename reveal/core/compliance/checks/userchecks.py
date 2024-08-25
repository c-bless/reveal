from sqlalchemy import and_

from reveal.core.sids import SID_LOCAL_ADMIN_GROUP
from reveal.core.sids import SID_BUILTIN_REMOTE_DESKTOP_USERS
from reveal.core.sids import SID_BUILTIN_REMOTE_MANAGEMENT_USERS
from reveal.core.sids import SID_BUILTIN_DCOM_USERS
from reveal.core.sids import SID_BUILTIN_PERFORMANCE_MONITOR_USERS

from reveal.core.models.sysinfo import Group
from reveal.core.models.sysinfo import GroupMember
from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import User


def verify_user_disabled(host: Host, username: str, accept_removed=True) -> bool:
    """
    Verifies if the specified user is disabled on the given host.

    This functions checks if the user is disabled on the given host. In case the accept_remove is set it also returns
    true if the account does not exist (e.g., has been removed).

    :param host: Host object retrieved from database
    :param username: the username that should be disabled
    :param accept_removed: specifies if a removed account is accepted as disabled
    :return: True if user has been disabled otherwise False is returned
    """
    result = False
    users = []
    for u in host.Users:
        users.append(u.Name)
        if u.Name == username and u.Disabled:
            result = True
    if accept_removed is True and username not in users:
        result = True
    return result


def verify_user_exists(host: Host, username: str, accept_disabled=False) -> bool:
    """
    Verifies if the given account exists.

    This function verifies if the specified user account exists on the given host. If the parameter accept_disabled is
    set, the function also returns True for existing but disabled accounts.

    :param host:
    :param username:
    :param accept_disabled:
    :return:
    """
    for u in host.Users:
        if u.Name == username:
            if u.Disabled is False:
                # user account is activated
                return True
            # user account has been found but it is disabled.
            elif accept_disabled is True:
                # disabled accounts are accepted
                return True
    # user account has not been found
    return False
