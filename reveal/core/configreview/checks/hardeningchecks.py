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


def verify_wsus_http(host: Host) -> ConfigReviewResult:
    """Verifies that WSUS is used via plain http (YAML: wsus: {https_enabled: False})."""
    result = ConfigReviewResult(check="WSUS via http", component="WSUS", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if host.WUServer is None or str(host.WUServer).strip() == "":
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    else:
        result.compliant = str(host.WUServer).strip().lower().startswith("http://")
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

LLMNR_CHECK_NAME = "LLMNR - Enabled"


def _normalize_status(value) -> str | None:
    """
    Normalizes an LLMNR status to "enabled" / "disabled" (None if unknown). Accepts the results of the collector
    ("Enabled", "Enabled (not configured)", "Disabled") as well as booleans from YAML.
    """
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    value = str(value or "").strip().lower()
    if value.startswith("enabled"):
        return "enabled"
    if value.startswith("disabled"):
        return "disabled"
    return None


def verify_llmnr_status(host: Host, expected) -> ConfigReviewResult:
    """
    Verifies the LLMNR status of a host (ConfigCheck "LLMNR - Enabled" of the sysinfo collector).

    YAML:
        system:
          llmnr:
            Status: Disabled    # or Enabled

    "Enabled (not configured)" (no group policy set) counts as enabled.
    """
    result = ConfigReviewResult(check=f"LLMNR {expected}", component="LLMNR", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    expected_status = _normalize_status(expected)
    if expected_status is None:
        result.compliant = False
        result.message = f"Invalid expected LLMNR status '{expected}' (allowed: Enabled, Disabled)"
        return result
    check = next((c for c in host.ConfigChecks if c.Component == "LLMNR" or c.Name == LLMNR_CHECK_NAME), None)
    current_status = _normalize_status(check.Result) if check is not None else None
    if current_status is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected"
    else:
        result.compliant = current_status == expected_status
        result.message = f"LLMNR is {check.Result}"
    return result


# WSUS settings (HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate), stored as strings in the Host table
WSUS_BOOL_FIELDS = ["DisableWindowsUpdateAccess", "ElevateNonAdmins", "TargetGroupEnabled"]
WSUS_STRING_FIELDS = ["WUServer", "WUStatusServer", "TargetGroup"]


def _bool_or_none(value) -> bool | None:
    """Registry DWORD / text ("1", "0", "True", "False") or YAML bool -> bool (None if unknown / not set)."""
    if isinstance(value, bool):
        return value
    value = str(value if value is not None else "").strip().lower()
    if value in ("1", "true", "yes", "enabled"):
        return True
    if value in ("0", "false", "no", "disabled"):
        return False
    return None


def verify_wsus_bool(host: Host, field: str, expected: bool) -> ConfigReviewResult:
    """Verifies a WSUS flag (DisableWindowsUpdateAccess, ElevateNonAdmins, TargetGroupEnabled)."""
    current_raw = getattr(host, field)
    result = ConfigReviewResult(check=f"WSUS {field} = {expected}", component="WSUS", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    current = _bool_or_none(current_raw)
    if current is None:
        result.compliant = False
        result.message = "UNKNOWN. Data not collected / not configured"
    else:
        result.compliant = current == bool(expected)
        result.message = f"{field}: {current} (value: {current_raw})"
    return result


def verify_wsus_string(host: Host, field: str, expected: str) -> ConfigReviewResult:
    """Verifies a WSUS setting (WUServer, WUStatusServer, TargetGroup). Case-insensitive, trailing "/" ignored."""
    current_raw = getattr(host, field)
    result = ConfigReviewResult(check=f"WSUS {field} = {expected}", component="WSUS", hostname=host.Hostname,
                                systemgroup=host.SystemGroup)
    if current_raw is None or str(current_raw).strip() == "":
        result.compliant = False
        result.message = "UNKNOWN. Data not collected / not configured"
    else:
        def normalize(v): return str(v).strip().rstrip("/").lower()
        result.compliant = normalize(current_raw) == normalize(expected)
        result.message = f"{field}: {current_raw}"
    return result


def verify_wsus_checks(host: Host, checks: dict) -> list[ConfigReviewResult]:
    """
    Dispatcher for the WSUS checks (keys are case-insensitive):

        wsus:
          https_enabled: True        # False: WSUS must be used via http
          WUServer: "https://domain.local:8531"
          WUStatusServer: "https://domain.local:8531"
          DisableWindowsUpdateAccess: True
          ElevateNonAdmins: False
          TargetGroup: "GROUPNAME"
          TargetGroupEnabled: True
    """
    results = []
    fields = {f.lower(): f for f in WSUS_BOOL_FIELDS + WSUS_STRING_FIELDS}
    for key, expected in checks.items():
        k = str(key).lower()
        if k == "https_enabled":
            expected_bool = _bool_or_none(expected)
            if expected_bool is True:
                results.append(verify_wsus_https(host))
            elif expected_bool is False:
                results.append(verify_wsus_http(host))
        elif k in fields and fields[k] in WSUS_BOOL_FIELDS:
            expected_bool = _bool_or_none(expected)
            if expected_bool is not None:
                results.append(verify_wsus_bool(host, fields[k], expected_bool))
        elif k in fields:
            if expected is not None:
                results.append(verify_wsus_string(host, fields[k], expected))
    return results
