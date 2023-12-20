from sqlalchemy import or_
from sqlalchemy import and_

from systemdb.core.models.sysinfo import Service
from systemdb.core.models.sysinfo import ServiceACL
from systemdb.core.models.sysinfo import RegistryCheck
from systemdb.core.models.sysinfo import Host


def find_uqsp(host_filter=[]) -> list[Service]:
    services = Service.query.filter(
        and_(
            Service.PathName.notlike('"%'),
            Service.PathName.contains(" "),
            Service.PathName.notilike(r'C:\\Windows%'))
    ).join(Host).filter(*host_filter).all()
    return services


def find_modifiable_services(host_filter=[]) -> list[ServiceACL]:
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
    acls = ServiceACL.query.filter(and_(*service_filter)).join(Service).join(Host).filter(and_(*host_filter)).all()
    return acls


def find_service_by_filter(service_filter=[], host_filter=[]) -> list[Service]:
    services = Service.query.filter(and_(*service_filter)).join(Host).filter(and_(*host_filter)).all()
    return services


def find_stickykeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Name == "HKCU:\\Control Panel\\Accessibility\\StickyKeys\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "506"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_togglekeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\Control Panel\\Accessibility\\ToggleKeys\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "58"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_filterkeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\Control Panel\\Accessibility\\Keyboard Response\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "122"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_mousekeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\Control Panel\\Accessibility\\MouseKeys\\",
            RegistryCheck.Key == "Flags",
            RegistryCheck.CurrentValue != "59"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_windowskeys_enabled(host_filter=[]) -> list[RegistryCheck]:
    checks = RegistryCheck.query.filter(
        and_(
            RegistryCheck.Path == "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\",
            RegistryCheck.Key == "NoWinKeys",
            RegistryCheck.CurrentValue != "0x1"
        )
    ).join(Host).filter(*host_filter).all()
    return checks


def find_hotkeys_enabled_dict(host_filter=[]) -> dict[str: RegistryCheck]:
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
