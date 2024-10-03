from sqlalchemy import and_

from reveal.core.models.sysinfo import Host, Service
from reveal.core.configreview import ComplianceResult, ConfigReviewResult


def verfiy_services_disabled(host: Host, services: list[str]) -> list[ConfigReviewResult]:
    """
    Verifies if the specified services are disabled on the given host.

    This functions checks if the services are disabled on the given host.

    :param host: Host object retrieved from database
    :param services: list of names of the services that should be disabled
    :return: list of results of compliance checks. `result.compliant` is True if service is disabled False otherwise.
    """
    results = []
    found_services = []
    disabled = []
    for s in host.Services:
        found_services.append(s.Name)
        if s.StartMode in ["Disabled", "Manual"]:
            disabled.append(s.Name)
    for s_in in services:
        result = ConfigReviewResult(component=s_in, check="service status checks (disabled)", hostname=host.Hostname,
                                    systemgroup=host.SystemGroup)
        if s_in in disabled:
            result.compliant = True
            result.message = f"Service ({s_in}) is disabled"
        elif s_in not in found_services:
            result.compliant = True
            result.message = f"Service ({s_in}) does not exist"
        else:
            result.compliant = False
            result.message = f"Service ({s_in}) not disabled"
        results.append(result)
    return results


def verify_services_running(host: Host, services: list[str]) -> list[ConfigReviewResult]:
    """
    Verifies if the specified services are enabled on the given host.

    This functions checks if the services are enabled on the given host.

    :param host: Host object retrieved from database
    :param services: list of names of the services that should be enabled
    :return: list of results of compliance checks. `result.compliant` is True if service is enabled False otherwise.
    """
    results = []
    running = []
    for s in host.Services:
        if s.Started is True:
            running.append(s.Name)
    for s_in in services:
        result = ConfigReviewResult(component=s_in, check="service status checks (running)", hostname=host.Hostname,
                                    systemgroup=host.SystemGroup)
        if s_in in running:
            result.compliant = True
            result.message = f"Service ({s_in}) is running"
        else:
            result.compliant = False
            result.message = f"Service ({s_in}) is not running"
        results.append(result)
    return results


def verify_services_not_running(host: Host, services: list[str]) -> list[ConfigReviewResult]:
    """
    Verifies if the specified services are not enabled on the given host.

    This functions checks if the services are not enabled on the given host.

    :param host: Host object retrieved from database
    :param services: list of names of the services that should not be enabled
    :return: list of results of compliance checks. `result.compliant` is True if service is not running False otherwise.
    """
    results = []
    found_services = []
    not_running = []
    for s in host.Services:
        if s.Started is False:
            not_running.append(s.Name)
        found_services.append(s.Name)
    for s_in in services:
        result = ConfigReviewResult(component=s_in, check="service status checks (not running)", hostname=host.Hostname,
                                    systemgroup=host.SystemGroup)
        if s_in not in found_services:
            result.compliant = True
            result.message = f"Service ({s_in}) does not exist"
        elif s_in in not_running:
            result.compliant = True
            result.message = f"Service ({s_in}) is not running"
        else:
            result.compliant = False
            result.message = f"Service ({s_in}) is running"
        results.append(result)
    return results
