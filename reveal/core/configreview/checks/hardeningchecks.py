
from reveal.core.models.sysinfo import Host
from reveal.core.compliance import ComplianceResult


def verify_firewall_enabled(host: Host, profiles = []) -> ComplianceResult:
    result = ComplianceResult(compliant=False)
    result_status = True
    profiles = [str.lower(p) for p in profiles]
    if "domain" in profiles:
        if host.FwProfileDomain is False:
            result_status = False
            result.messages.append(f"Firewall is disabled for profile 'domain'!")
    if "public" in profiles:
        if host.FwProfilePublic is False:
            result_status = False
            result.messages.append(f"Firewall is disabled for profile 'public'!")
    if "private" in profiles:
        if host.FwProfilePrivate is False:
            result_status = False
            result.messages.append(f"Firewall is disabled for profile 'private'!")
    result.compliant = result_status
    return result


def verify_firewall_disabled(host: Host, profiles = []) -> ComplianceResult:
    result = ComplianceResult(compliant=False)
    result_status = True
    profiles = [str.lower(p) for p in profiles]
    if "domain" in profiles:
        if host.FwProfileDomain is True:
            result_status = False
            result.messages.append(f"Firewall is enabled for profile 'domain'!")
    if "public" in profiles:
        if host.FwProfilePublic is True:
            result_status = False
            result.messages.append(f"Firewall is enabled for profile 'public'!")
    if "private" in profiles:
        if host.FwProfilePrivate is True:
            result_status = False
            result.messages.append(f"Firewall is enabled for profile 'private'!")
    result.compliant = result_status
    return result


def verify_smbv1_disabled(host: Host) -> ComplianceResult:
    result = ComplianceResult(compliant=False)
    if host.SMBv1Enabled is False:
        result.compliant = True
    else:
        result.messages.append("SMBv1 is enabled!")
    return result


def verify_smbv_signing_enabled(host: Host) -> ComplianceResult:
    result = ComplianceResult(compliant=False)
    if host.SMBEnableSecuritySignature is True:
        result.compliant = True
    else:
        result.messages.append("SMB signing is disabled!")
    return result


def verify_smbv_signing_required(host: Host) -> ComplianceResult:
    result = ComplianceResult(compliant=False)
    if host.SMBRequireSecuritySignature is True:
        result.compliant = True
    else:
        result.messages.append("SMB signing is not required!")
    return result


def verify_wsus_https(host: Host) -> ComplianceResult:
    result = ComplianceResult(compliant=False)
    server = str(host.WUServer)
    if server.startswith("https://"):
        result.compliant = True
    else:
        result.messages.append("WSUS schould be configured for use with HTTPS!")
    return result

