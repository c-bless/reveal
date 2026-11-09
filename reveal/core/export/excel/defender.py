from io import BytesIO

import xlsxwriter


def generate_defender_excel(hosts=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []
    header_data = ["Hostname", "Domain", "OSName", "SystemGroup", "Location", "Label", "AMEngineVersion",
                   "AMProductVersion", "AMServiceEnabled", "AMServiceVersion", "AntispywareEnabled",
                   "AntispywareSignatureLastUpdated", "AntispywareSignatureVersion", "AntivirusEnabled",
                   "AntivirusSignatureLastUpdated",
                   "AntivirusSignatureVersion", "BehaviorMonitorEnabled", "IoavProtectionEnabled", "IsVirtualMachine",
                   "NISEnabled",
                   "NISEngineVersion", "NISSignatureLastUpdated", "NISSignatureVersion", "OnAccessProtectionEnabled",
                   "RealTimeProtectionEnabled", "DisableArchiveScanning", "DisableAutoExclusions", "DisableBehaviorMonitoring",
                   "DisableBlockAtFirstSeen", "DisableCatchupFullScan", "DisableCatchupQuickScan", "DisableEmailScanning",
                   "DisableIntrusionPreventionSystem", "DisableIOAVProtection", "DisableRealtimeMonitoring",
                   "DisableRemovableDriveScanning", "DisableScanningMappedNetworkDrivesForFullScan",
                   "DisableScanningNetworkFiles", "DisableScriptScanning", "EnableNetworkProtection", "ExclusionPath", "ExclusionProcess"]

    for h in hosts:
        host_row = [h.Hostname, h.Domain, h.OSName, h.SystemGroup, h.Location, h.Label, "", "", "", "", "", "", "",
                    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""]
        for status in h.DefenderStatus:
            host_row[6] = status.AMEngineVersion
            host_row[7] = status.AMProductVersion
            host_row[8] = status.AMServiceEnabled
            host_row[9] = status.AMServiceVersion
            host_row[10] = status.AntispywareEnabled
            host_row[11] = status.AntispywareSignatureLastUpdated
            host_row[12] = status.AntispywareSignatureVersion
            host_row[13] = status.AntivirusEnabled
            host_row[14] = status.AntivirusSignatureLastUpdated
            host_row[15] = status.AntivirusSignatureVersion
            host_row[16] = status.BehaviorMonitorEnabled
            host_row[17] = status.IoavProtectionEnabled
            host_row[18] = status.IsVirtualMachine
            host_row[19] = status.NISEnabled
            host_row[20] = status.NISEngineVersion
            host_row[21] = status.NISSignatureLastUpdated
            host_row[22] = status.NISSignatureVersion
            host_row[23] = status.OnAccessProtectionEnabled
            host_row[24] = status.RealTimeProtectionEnabled
        for settings in h.DefenderSettings:
            host_row[25] = settings.DisableArchiveScanning
            host_row[26] = settings.DisableAutoExclusions
            host_row[27] = settings.DisableBehaviorMonitoring
            host_row[28] = settings.DisableBlockAtFirstSeen
            host_row[29] = settings.DisableCatchupFullScan
            host_row[30] = settings.DisableCatchupQuickScan
            host_row[31] = settings.DisableEmailScanning
            host_row[32] = settings.DisableIntrusionPreventionSystem
            host_row[33] = settings.DisableIOAVProtection
            host_row[34] = settings.DisableRealtimeMonitoring
            host_row[35] = settings.DisableRemovableDriveScanning
            host_row[36] = settings.DisableScanningMappedNetworkDrivesForFullScan
            host_row[37] = settings.DisableScanningNetworkFiles
            host_row[38] = settings.DisableScriptScanning
            host_row[39] = settings.EnableNetworkProtection
            host_row[40] = settings.ExclusionPath
            host_row[41] = settings.ExclusionProcess
        rows.append(host_row)

    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    cell_format = workbook.add_format({'text_wrap': True})

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for service in rows:
        for c in service:
            worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    worksheet.autofilter("A1:AP1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output


def _write_table(header, rows):
    """
    Writes a table to a new Excel workbook. All values are written as text (write_string), so values collected from
    the hosts (e.g. exclusion paths starting with "=") are not interpreted as formulas.
    """
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()
    header_format = workbook.add_format({'bold': True, 'bottom': 2, 'bg_color': '#CCCCCC'})
    for col, title in enumerate(header):
        worksheet.write_string(0, col, title, header_format)
    for row, values in enumerate(rows, start=1):
        for col, value in enumerate(values):
            worksheet.write_string(row, col, "" if value is None else str(value))
    worksheet.autofilter(0, 0, max(len(rows), 1), len(header) - 1)
    worksheet.autofit()
    workbook.close()
    output.seek(0)
    return output


def _host_columns(h):
    return [h.Hostname, h.Domain, h.OSName, h.SystemGroup, h.Location, h.Label]


HOST_HEADER = ["Hostname", "Domain", "OSName", "SystemGroup", "Location", "Label"]


def generate_defender_protection_excel(hosts, status_by_host):
    """ Hosts with the state of all protection components and the list of disabled components. """
    from reveal.core.querries.defender import PROTECTION_COMPONENTS, disabled_components
    header = HOST_HEADER + [field for field, _ in PROTECTION_COMPONENTS] + ["Disabled components"]
    rows = []
    for h in hosts:
        for s in status_by_host.get(h.id, []):
            rows.append(_host_columns(h) + [getattr(s, field) for field, _ in PROTECTION_COMPONENTS]
                        + [", ".join(disabled_components(s))])
    return _write_table(header, rows)


def generate_defender_exclusions_excel(hosts, settings_by_host):
    """ Hosts with the configured exclusion paths and processes. """
    header = HOST_HEADER + ["ExclusionPath", "ExclusionProcess"]
    rows = []
    for h in hosts:
        for s in settings_by_host.get(h.id, []):
            rows.append(_host_columns(h) + [s.ExclusionPath, s.ExclusionProcess])
    return _write_table(header, rows)
