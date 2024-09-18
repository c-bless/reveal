from sqlalchemy import and_

from reveal.core.models.sysinfo import Host, Service
from reveal.core.compliance import ComplianceResult


def verify_service_disabled(host: Host, service_name: str) -> ComplianceResult:
    """
    Verifies if the specified service is disabled on the given host.

    This functions checks if the service is disabled on the given host.

    :param host: Host object retrieved from database
    :param service_name: the name of the service that should be disabled

    :return: result of compliance check. `result.compliant` is True if service is disabled False otherwise.
    """
    result = ComplianceResult(compliant=True)
    services = []
    for s in host.Services:
        services.append(s.Name)
        if s.Name == service_name and s.Started:
            result.compliant = False
            result.messages.append(f"service '{s.Name}' is enabled but was expected to be disabled.")
    return result


def verify_service_enabled(host: Host, service_name: str) -> ComplianceResult:
    """
    Verifies if the specified service is enabled on the given host.

    This functions checks if the service is enabled on the given host.

    :param host: Host object retrieved from database
    :param service_name: the name of the service that should be enabled

    :return: result of compliance check. `result.compliant` is True if service is enabled False otherwise.
    """
    result = ComplianceResult(compliant=True)
    services = []
    for s in host.Services:
        services.append(s.Name)
        if s.Name == service_name and not s.Started:
            result.compliant = False
            result.messages.append(f"service '{s.Name}' is disabled but was expected to be enabled.")
    return result


def verify_service_autostart(host: Host, service_name: str) -> ComplianceResult:
    result = ComplianceResult(compliant=False)
    for s in host.Services:
        if s.Name == service_name and ("auto" in s.StartMode or "Auto" in s.StartMode):
            result.compliant = True
        else:
            result.compliant = False
            result.messages.append(f"service '{s.NameName}' has autostart enabled.")
    return result