from reveal.core.configreview import ConfigReviewResult
from reveal.core.models.sysinfo import Host


def verify_user_disabled(host: Host, username: str, accept_removed=True) -> ConfigReviewResult:
    """
    Verifies if the specified user is disabled on the given host.

    This functions checks if the user is disabled on the given host. In case the accept_remove is set it also returns
    true if the account does not exist (e.g., has been removed).

    :param host: Host object retrieved from database
    :param username: the username that should be disabled
    :param accept_removed: specifies if a removed account is accepted as disabled

    :return: result of compliance check. `result.compliant` is `True` if user is disabled `False` otherwise.
    """
    result = ConfigReviewResult(check="User disabled check", component=username, hostname=host.Hostname, systemgroup=host.SystemGroup)
    users = []
    for u in host.Users:
        users.append(u.Name)
        if u.Name == username and u.Disabled:
            result.compliant = True
            result.message = f"User {username} is disabled."
        elif u.Name == username:
            result.compliant = False
            result.message = f"User {username} is not disabled."
    if accept_removed is True and username not in users:
        result.compliant = True
        result.message = "user does not exist"
    return result


def verify_user_exists(host: Host, username: str, accept_disabled=False) -> ConfigReviewResult:
    """
    Verifies if the given account exists.

    This function verifies if the specified user account exists on the given host. If the parameter accept_disabled is
    set, the function also returns True for existing but disabled accounts.

    :param host:
    :param username:
    :param accept_disabled:
    :return:
    """
    result = ConfigReviewResult(check="User exist check", component=username, hostname=host.Hostname, systemgroup=host.SystemGroup)
    found = False
    for u in host.Users:
        if u.Name == username:
            found = True
            if u.Disabled is False:
                # user account is activated
                result.compliant = True
                result.compliant = f"user {username} is active"
            # user account has been found but it is disabled.
            elif accept_disabled is True:
                # disabled accounts are accepted
                result.compliant = True
                result.message =  f"user {username} exists but is disabled"
            else:
                result.compliant = False
                result.message = f"User {username} exists but is disabled."
    if found is False:
        # user account has not been found
        result.message = f"User {username} does not exist."
    return result
