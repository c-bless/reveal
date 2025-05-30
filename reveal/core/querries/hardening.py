from sqlalchemy import or_
from sqlalchemy import and_

from reveal.core.models.sysinfo import Service
from reveal.core.models.sysinfo import ServiceACL
from reveal.core.models.sysinfo import RegistryCheck
from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import ConfigCheck


def find_uqsp(host_filter=[]) -> list[Service]:
    """
    Finds services with unquoted service paths.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[Service]: List of services with unquoted service paths.
    """
    services = Service.query.filter(
        and_(
            Service.PathName.notlike('"%'),
            Service.PathName.like("% %"),
            Service.PathName.notilike(r'C:\\Windows%'))
    ).join(Host).filter(*host_filter).all()
    return services


def find_modifiable_services(host_filter=[]) -> list[ServiceACL]:
    """
    Finds services with access control lists (ACLs) allowing modification of service binaries.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[ServiceACL]: List of service ACLs with modifiable permissions.
    """
    acls = ServiceACL.query.filter(
        or_(
            and_(
                ServiceACL.AccessRight.ilike("%Modify%"),
                ServiceACL.AccountName.notilike("%System"),
                ServiceACL.AccountName.notilike("%TrustedInstaller"),
                ServiceACL.AccountName.notilike("%Administra%"),
            ),
            and_(
                ServiceACL.AccessRight.ilike("%FullControl%"),
                ServiceACL.AccountName.notilike("%System"),
                ServiceACL.AccountName.notilike("%TrustedInstaller"),
                ServiceACL.AccountName.notilike("%Administra%"),
            )
        )
    ).join(Service).join(Host).filter(and_(*host_filter)).all()
    return acls


def find_serviceACL_by_filter(service_filter=[], host_filter=[]) -> list[ServiceACL]:
    """
    Finds service ACLs based on specified filters.

    Args:
        service_filter (list, optional): List of filters to apply to the service query. Defaults to [].
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[ServiceACL]: List of service ACLs matching the specified filters.
    """
    acls = ServiceACL.query.filter(and_(*service_filter)).join(Service).join(Host).filter(and_(*host_filter)).all()
    return acls


def find_service_by_filter(service_filter=[], host_filter=[]) -> list[Service]:
    """
    Finds service ACLs based on specified filters.

    Args:
        service_filter (list, optional): List of filters to apply to the service query. Defaults to [].
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[ServiceACL]: List of service ACLs matching the specified filters.
    """
    services = Service.query.filter(and_(*service_filter)).join(Host).filter(and_(*host_filter)).all()
    return services


def find_stickykeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    """
    Finds registry checks for enabled StickyKeys.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[RegistryCheck]: List of registry checks for enabled StickyKeys.
    """
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Name == "HKCU:\\Control Panel\\Accessibility\\StickyKeys\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "506"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_togglekeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    """
    Finds registry checks for enabled ToggleKeys.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[RegistryCheck]: List of registry checks for enabled ToggleKeys.
    """
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\Control Panel\\Accessibility\\ToggleKeys\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "58"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_filterkeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    """
    Finds registry checks for enabled FilterKeys.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[RegistryCheck]: List of registry checks for enabled FilterKeys.
    """
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\Control Panel\\Accessibility\\Keyboard Response\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "122"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_mousekeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    """
    Finds registry checks for enabled MouseKeys.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[RegistryCheck]: List of registry checks for enabled MouseKeys.
    """
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\Control Panel\\Accessibility\\MouseKeys\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "59"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_windowskeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    """
    Finds registry checks for enabled Windows keys (e.g. WINDOWS + E).

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[RegistryCheck]: List of registry checks for enabled Windows keys.
    """
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\",
            RegistryCheck.Key == "NoWinKeys",
            RegistryCheck.CurrentValue != "0x1"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_hotkeys_enabled_dict(host_filter=[]) -> dict[str: RegistryCheck]:
    """
    Finds registry checks for various enabled hotkeys and returns them as a dictionary.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        dict[str, list[RegistryCheck]]: Dictionary with hotkey names as keys and lists of registry checks as values.
    """
    sticky_keys = find_stickykeys_enabled(host_filter=host_filter)
    toggle_keys = find_togglekeys_enabled(host_filter=host_filter)
    filter_keys = find_filterkeys_enabled(host_filter=host_filter)
    windows_keys = find_windowskeys_enabled(host_filter=host_filter)
    mouse_keys = find_mousekeys_enabled(host_filter=host_filter)

    result = {
        "StickyKeys enabled": sticky_keys,
        "ToggleKeys enabled": toggle_keys,
        "FilterKeys enabled": filter_keys,
        "MouseKeys enabled": mouse_keys,
        "Windows Keys enabled": windows_keys
    }

    return result


def find_hotkeys_enabled_list(host_filter=[]) -> list[RegistryCheck]:
    """
    Finds registry checks for various enabled hotkeys and returns them as a list.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[RegistryCheck]: List of registry checks for enabled hotkeys.
    """
    sticky_keys = find_stickykeys_enabled(host_filter=host_filter)
    toggle_keys = find_togglekeys_enabled(host_filter=host_filter)
    filter_keys = find_filterkeys_enabled(host_filter=host_filter)
    windows_keys = find_windowskeys_enabled(host_filter=host_filter)
    mouse_keys = find_mousekeys_enabled(host_filter=host_filter)

    result = []
    result.extend(sticky_keys)
    result.extend(toggle_keys)
    result.extend(filter_keys)
    result.extend(windows_keys)
    result.extend(mouse_keys)

    return result


def find_hosts_with_LLMNR(host_filter=[]) -> list[ConfigCheck]:
    """
    Finds hosts with Link-Local Multicast Name Resolution (LLMNR) enabled.

    Args:
        host_filter (list, optional): List of filters to apply to the host query. Defaults to [].

    Returns:
        list[ConfigCheck]: List of configuration checks for hosts with LLMNR enabled.
    """
    checks = ConfigCheck.query.filter(
        and_(
            ConfigCheck.Component == "LLMNR",
            ConfigCheck.Result.ilike("Enabled%")
        )
    ).join(Host).filter(*host_filter).all()
    return checks
