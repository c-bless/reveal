from reveal.core.models.sysinfo import Host, DefenderStatus, DefenderSettings, NETWORK_PROTECTION_STATES
from reveal.core.configreview import ConfigReviewResult
from reveal.core.querries.defender import NOT_READABLE_PREFIX
from reveal.core.importer.converter import network_protection_or_none

# boolean fields that can be checked against an expected value (keys in the YAML section "Defender")
DEFENDER_STATUS_FIELDS = ("AMServiceEnabled", "AntispywareEnabled", "AntivirusEnabled", "BehaviorMonitorEnabled",
                          "IoavProtectionEnabled", "NISEnabled", "OnAccessProtectionEnabled",
                          "RealTimeProtectionEnabled")
DEFENDER_SETTINGS_FIELDS = ("DisableArchiveScanning", "DisableAutoExclusions", "DisableBehaviorMonitoring",
                            "DisableBlockAtFirstSeen", "DisableCatchupFullScan", "DisableCatchupQuickScan",
                            "DisableEmailScanning", "DisableIntrusionPreventionSystem", "DisableIOAVProtection",
                            "DisableRealtimeMonitoring", "DisableRemovableDriveScanning", "DisableRestorePoint",
                            "DisableScanningMappedNetworkDrivesForFullScan", "DisableScanningNetworkFiles",
                            "DisableScriptScanning")
EXCLUSION_FIELDS = ("ExclusionPath", "ExclusionProcess")

UNKNOWN_MESSAGE = "UNKNOWN. Data not collected"


def _latest_status(host: Host) -> DefenderStatus | None:
    return host.DefenderStatus.order_by(DefenderStatus.id.desc()).first()


def _latest_settings(host: Host) -> DefenderSettings | None:
    return host.DefenderSettings.order_by(DefenderSettings.id.desc()).first()


def _result(host: Host, check: str) -> ConfigReviewResult:
    return ConfigReviewResult(check=check, component="Defender", hostname=host.Hostname,
                              systemgroup=host.SystemGroup)


def verify_defender_value(host: Host, field: str, expected: bool) -> ConfigReviewResult:
    """
    Compares a boolean field of DefenderStatus (Get-MpComputerStatus) or DefenderSettings (Get-MpPreference) with
    the expected value. The latest collected entry of the host is used.
    """
    result = _result(host, f"Defender {field} = {expected}")
    if field in DEFENDER_STATUS_FIELDS:
        entry = _latest_status(host)
    elif field in DEFENDER_SETTINGS_FIELDS:
        entry = _latest_settings(host)
    else:
        result.compliant = False
        result.message = f"Unsupported Defender field '{field}'"
        return result

    value = getattr(entry, field) if entry is not None else None
    if value is None:
        result.compliant = False
        result.message = UNKNOWN_MESSAGE
    else:
        result.compliant = value is expected
        result.message = f"{field} is {value} (expected: {expected})"
    return result


def verify_defender_network_protection(host: Host, expected) -> ConfigReviewResult:
    """
    Compliant if EnableNetworkProtection has one of the expected values: 0 = disabled, 1 = enabled (block mode),
    2 = audit mode. Expected can be a single value or a list (e.g. [1, 2]), True / False are mapped to 1 / 0.
    """
    expected_values = expected if isinstance(expected, list) else [expected]
    allowed = [network_protection_or_none(v) for v in expected_values]
    allowed = [v for v in allowed if v is not None]
    labels = ", ".join(NETWORK_PROTECTION_STATES.get(v, str(v)) for v in allowed)
    result = _result(host, f"Defender network protection ({labels})")

    settings = _latest_settings(host)
    if settings is None or settings.EnableNetworkProtection is None:
        result.compliant = False
        result.message = UNKNOWN_MESSAGE
    else:
        result.compliant = settings.EnableNetworkProtection in allowed
        result.message = f"Network protection: {settings.NetworkProtectionState} (expected: {labels})"
    return result


def _exclusions(host: Host, field: str) -> tuple[str | None, str | None]:
    """
    Returns (exclusions, error message). Exclusions is "" if none are configured. The collector writes the list as
    one string (items separated by spaces), "None" for empty values (legacy importer) and "N/A: ..." if the
    collector did not run with administrative privileges.
    """
    settings = _latest_settings(host)
    if settings is None:
        return None, UNKNOWN_MESSAGE
    value = getattr(settings, field)
    if value is None or value.strip() in ("", "None"):
        return "", None
    if value.startswith(NOT_READABLE_PREFIX):
        return None, f"UNKNOWN. {field} not readable (collector without administrative privileges)"
    return value.strip(), None


def verify_defender_exclusions_not_set(host: Host, field: str) -> ConfigReviewResult:
    """ Compliant if no exclusions of the given type (ExclusionPath / ExclusionProcess) are configured. """
    result = _result(host, f"Defender {field} not set")
    value, error = _exclusions(host, field)
    if error:
        result.compliant = False
        result.message = error
    elif value == "":
        result.compliant = True
        result.message = f"No {field} configured"
    else:
        result.compliant = False
        result.message = f"{field}: {value}"
    return result


def verify_defender_exclusions_not_contain(host: Host, field: str, patterns: list[str]) -> list[ConfigReviewResult]:
    """ Compliant if the exclusions do not contain the pattern (case-insensitive substring). One result per pattern. """
    results = []
    value, error = _exclusions(host, field)
    for p in patterns:
        result = _result(host, f"Defender {field} does not contain '{p}'")
        if error:
            result.compliant = False
            result.message = error
        elif str(p).lower() in value.lower():
            result.compliant = False
            result.message = f"{field}: {value}"
        else:
            result.compliant = True
            result.message = f"'{p}' not excluded"
        results.append(result)
    return results


def verify_defender_exclusions_contain(host: Host, field: str, patterns: list[str]) -> list[ConfigReviewResult]:
    """ Compliant if the exclusions contain the pattern (case-insensitive substring), e.g. required exclusions of a
    vendor. One result per pattern. """
    results = []
    value, error = _exclusions(host, field)
    for p in patterns:
        result = _result(host, f"Defender {field} contains '{p}'")
        if error:
            result.compliant = False
            result.message = error
        elif str(p).lower() in value.lower():
            result.compliant = True
            result.message = f"'{p}' is excluded"
        else:
            result.compliant = False
            result.message = f"'{p}' is not excluded"
        results.append(result)
    return results


def verify_defender_checks(host: Host, checks: dict) -> list[ConfigReviewResult]:
    """
    Runs the checks of the YAML section system -> Defender:
      <boolean field>: True|False          expected value of a DefenderStatus / DefenderSettings field
      EnableNetworkProtection: 1|[1, 2]    0 = disabled, 1 = enabled (block mode), 2 = audit mode
      <ExclusionPath|ExclusionProcess>NotSet: True
      <ExclusionPath|ExclusionProcess>NotContains: [patterns]
      <ExclusionPath|ExclusionProcess>Contains: [patterns]
    """
    results = []
    for key, expected in checks.items():
        if key in DEFENDER_STATUS_FIELDS or key in DEFENDER_SETTINGS_FIELDS:
            if isinstance(expected, bool):
                results.append(verify_defender_value(host, key, expected))
            continue
        if key == "EnableNetworkProtection":
            results.append(verify_defender_network_protection(host, expected))
            continue
        for field in EXCLUSION_FIELDS:
            patterns = expected if isinstance(expected, list) else [expected]
            if key == f"{field}NotSet" and expected is True:
                results.append(verify_defender_exclusions_not_set(host, field))
            elif key == f"{field}NotContains":
                results.extend(verify_defender_exclusions_not_contain(host, field, patterns))
            elif key == f"{field}Contains":
                results.extend(verify_defender_exclusions_contain(host, field, patterns))
    return results
