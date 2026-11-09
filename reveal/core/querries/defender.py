"""
Queries for the Microsoft Defender information of hosts (DefenderStatus = Get-MpComputerStatus,
DefenderSettings = Get-MpPreference).

All filters are conditions on Host (EXISTS subqueries), so they can be combined with other host filters and a host
is returned only once, even if there are several Defender entries for the host.
"""
from sqlalchemy import and_, or_, not_, exists, func

from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import DefenderStatus
from reveal.core.models.sysinfo import DefenderSettings


# protection components of DefenderStatus: (field name, label)
PROTECTION_COMPONENTS = [
    ("RealTimeProtectionEnabled", "Real-time protection"),
    ("AntivirusEnabled", "Antivirus"),
    ("AMServiceEnabled", "Defender service"),
    ("BehaviorMonitorEnabled", "Behavior monitoring"),
    ("IoavProtectionEnabled", "Download / attachment scanning (IOAV)"),
    ("OnAccessProtectionEnabled", "On-access protection"),
    ("NISEnabled", "Network inspection (NIS)"),
]

# values of ExclusionPath / ExclusionProcess that do not contain exclusions:
# "None" is written by the legacy importer for empty values, Defender returns "N/A: Must be an administrator to view
# exclusions" if the collector did not run with administrative privileges.
NOT_READABLE_PREFIX = "N/A"


def _status_exists(*conditions):
    return exists().where(and_(DefenderStatus.Host_id == Host.id, *conditions))


def _settings_exists(*conditions):
    return exists().where(and_(DefenderSettings.Host_id == Host.id, *conditions))


def protection_component_filter(field: str, enabled: bool):
    """ Hosts where the protection component (field of DefenderStatus) is enabled / disabled. """
    return _status_exists(getattr(DefenderStatus, field) == enabled)


def any_protection_disabled_filter():
    """ Hosts where at least one protection component is disabled. """
    return _status_exists(or_(*[getattr(DefenderStatus, f) == False for f, _ in PROTECTION_COMPONENTS]))


def _has_value(column):
    """ column contains real exclusions (not empty, not "None", not "N/A: ...") """
    return and_(column.isnot(None), func.trim(column) != "", column != "None",
                not_(column.like(NOT_READABLE_PREFIX + "%")))


def has_exclusions_filter():
    """ Hosts with configured exclusions (paths or processes). """
    return _settings_exists(or_(_has_value(DefenderSettings.ExclusionPath),
                                _has_value(DefenderSettings.ExclusionProcess)))


def exclusions_not_readable_filter():
    """ Hosts where the exclusions could not be read (collector without administrative privileges). """
    return _settings_exists(or_(DefenderSettings.ExclusionPath.like(NOT_READABLE_PREFIX + "%"),
                                DefenderSettings.ExclusionProcess.like(NOT_READABLE_PREFIX + "%")))


def no_exclusions_filter():
    """ Hosts with Defender settings, readable exclusions and without configured exclusions. """
    return and_(_settings_exists(), not_(has_exclusions_filter()), not_(exclusions_not_readable_filter()))


def exclusion_contains_filter(text: str):
    """ Hosts with an exclusion path or process containing the text (case-insensitive). """
    pattern = "%" + text + "%"
    return _settings_exists(or_(DefenderSettings.ExclusionPath.ilike(pattern),
                                DefenderSettings.ExclusionProcess.ilike(pattern)))


def no_defender_data_filter():
    """ Hosts without any Defender information (neither status nor settings collected). """
    return and_(not_(_status_exists()), not_(_settings_exists()))


def get_defender_data(hosts) -> tuple[dict, dict]:
    """
    Loads the Defender status and settings of the hosts with two queries.

    :return: (status_by_host, settings_by_host) - dictionaries {host id: [entries]}
    """
    status_by_host, settings_by_host = {}, {}
    host_ids = [h.id for h in hosts]
    if host_ids:
        for s in DefenderStatus.query.filter(DefenderStatus.Host_id.in_(host_ids)).order_by(DefenderStatus.id):
            status_by_host.setdefault(s.Host_id, []).append(s)
        for s in DefenderSettings.query.filter(DefenderSettings.Host_id.in_(host_ids)).order_by(DefenderSettings.id):
            settings_by_host.setdefault(s.Host_id, []).append(s)
    return status_by_host, settings_by_host


def disabled_components(status: DefenderStatus) -> list[str]:
    """ Labels of the disabled protection components of a DefenderStatus entry. """
    return [label for field, label in PROTECTION_COMPONENTS if getattr(status, field) is False]


def find_hosts_protection_disabled(host_filter=[]) -> list[Host]:
    return Host.query.filter(any_protection_disabled_filter(), and_(*host_filter)).order_by(Host.Hostname).all()


def find_hosts_with_exclusions(host_filter=[]) -> list[Host]:
    return Host.query.filter(has_exclusions_filter(), and_(*host_filter)).order_by(Host.Hostname).all()


def find_hosts_without_defender_data(host_filter=[]) -> list[Host]:
    return Host.query.filter(no_defender_data_filter(), and_(*host_filter)).order_by(Host.Hostname).all()
