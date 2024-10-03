from reveal.core.models.sysinfo import Host
from reveal.core.configreview import ConfigReviewResult


def verify_firewall_enabled(host: Host, profiles: list[str]) -> list[ConfigReviewResult]:
    results = []
    allowed_profiles = ["domain", "public", "private"]
    profiles = [str.lower(p) for p in profiles if str.lower(p) in allowed_profiles]
    for p in profiles:
        result = ConfigReviewResult(check=f"firewall status ({p})", component=p, hostname=host.Hostname,
                                    systemgroup=host.SystemGroup)
        if "domain" == p:
            if host.FwProfileDomain is False:
                result.compliant = False
            else:
                result.compliant = True
        if "public" in profiles:
            if host.FwProfilePublic is False:
                result.compliant = False
            else:
                result.compliant = True
        if "private" in profiles:
            if host.FwProfilePrivate is False:
                result.compliant = False
            else:
                result.compliant = True
        if result.compliant is True:
            result.message = f"Firewall is enabled for profile '{p}'!"
        else:
            result.message = f"Firewall is disabled for profile '{p}'!"
        results.append(result)
    return results


def verify_firewall_disabled(host: Host, profiles=[]) -> list[ConfigReviewResult]:
    results = []
    allowed_profiles = ["domain", "public", "private"]
    profiles = [str.lower(p) for p in profiles if str.lower(p) in allowed_profiles]
    for p in profiles:
        result = ConfigReviewResult(check=f"firewall status ({p})", component=p, hostname=host.Hostname,
                                    systemgroup=host.SystemGroup)
        if "domain" == p:
            if host.FwProfileDomain is True:
                result.compliant = False
            else:
                result.compliant = True
        if "public" in profiles:
            if host.FwProfilePublic is True:
                result.compliant = False
            else:
                result.compliant = True
        if "private" in profiles:
            if host.FwProfilePrivate is True:
                result.compliant = False
            else:
                result.compliant = True
        if result.compliant is True:
            result.message = f"Firewall is enabled for profile '{p}'!"
        else:
            result.message = f"Firewall is disabled for profile '{p}'!"
        results.append(result)
    return results


def verify_smbv1_disabled(host: Host) -> ConfigReviewResult:
    result = ConfigReviewResult(check="SMBv1 disabled", component="SMB", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if host.SMBv1Enabled is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    elif host.SMBv1Enabled is False:
        result.compliant = True
        result.message = "SMBv1 is disabled!"
    else:
        result.compliant = False
        result.message = "SMBv1 is enabled!"
    return result


def verify_smbv1_enabled(host: Host) -> ConfigReviewResult:
    result = ConfigReviewResult(check="SMBv1 enabled", component="SMB", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if host.SMBv1Enabled is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    elif host.SMBv1Enabled is True:
        result.compliant = True
        result.message = "SMBv1 is enabled!"
    else:
        result.compliant = False
        result.message = "SMBv1 is disabled!"
    return result


def verify_smb_signing_enabled(host: Host) -> ConfigReviewResult:
    result = ConfigReviewResult(check="SMB signing enabled", component="SMB", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if host.SMBEnableSecuritySignature is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    elif host.SMBEnableSecuritySignature is True:
        result.compliant = True
        result.message = "SMB signing is enabled"
    else:
        result.compliant = True
        result.message = "SMB signing is disabled"
    return result


def verify_smb_signing_disabled(host: Host) -> ConfigReviewResult:
    result = ConfigReviewResult(check="SMB signing disabled", component="SMB", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if host.SMBEnableSecuritySignature is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    elif host.SMBEnableSecuritySignature is False:
        result.compliant = True
        result.message = "SMB signing is disabled"
    else:
        result.compliant = True
        result.message = "SMB signing is enabled"
    return result


def verify_smb_signing_required(host: Host) -> ConfigReviewResult:
    result = ConfigReviewResult(check="SMB signing required", component="SMB", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if host.SMBRequireSecuritySignature is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    elif host.SMBRequireSecuritySignature is True:
        result.compliant = True
        result.message = "SMB signing is required!"
    else:
        result.compliant = False
        result.message = "SMB signing is not required!"
    return result


def verify_smb_signing_not_required(host: Host) -> ConfigReviewResult:
    result = ConfigReviewResult(check="SMB signing not required", component="SMB", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if host.SMBRequireSecuritySignature is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    elif host.SMBRequireSecuritySignature is False:
        result.compliant = True
        result.message = "SMB signing is not required!"
    else:
        result.compliant = False
        result.message = "SMB signing is required!"
    return result


def verify_wsus_https(host: Host) -> ConfigReviewResult:
    result = ConfigReviewResult(check="WSUS via https", component="WSUS", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    server = str(host.WUServer)
    if host.WUServer is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    elif server.startswith("https://"):
        result.compliant = True
        result.message = f"WSUS URI: {host.WUServer}"
    else:
        result.compliant = False
        result.message = f"WSUS URI: {host.WUServer}"
    return result


def verify_configchecks(host: Host, checks: list) -> list[ConfigReviewResult]:
    results = []
    performed_checks = []
    for c_in in host.ConfigChecks:
        performed_checks.append(c_in.Name)
    for c in checks:
        if "name" in c and "result" in c:
            result = ConfigReviewResult(check=c["name"], component="ConfigCheck", hostname=host.Hostname,
                                        systemgroup=host.SystemGroup)
            if c["name"] in performed_checks:
                for cc in host.ConfigChecks:
                    if c["name"] == cc.Name:
                        if c["result"] == cc.Result:
                            result.compliant = True
                            result.message = "Result matches"
                        else:
                            result.compliant = False
                            result.message = "Result does not match"
            else:
                result.compliant = False
                result.message = "Data not collected"
            results.append(result)
    return results
