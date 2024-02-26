from io import BytesIO

import xlsxwriter


def generate_services_excel(services=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for s in services:
        tmp = [s.SystemName, s.Caption, s.Description, s.Name, s.StartMode, s.PathName, s.Started, s.StartName,
               s.DisplayName, s.AcceptStop, s.AcceptPause, s.ProcessId, s.DelayedAutoStart,
               s.BinaryPermissionsStr, s.Host, s.Host.SystemGroup, s.Host.Location, s.Host.Label]
        rows.append(tmp)


    header_data = ["SystemName", "Caption", "Description", "Name", "StartMode", "PathName", "Started", "StartName",
               "DisplayName", "AcceptStop", "AcceptPause", "ProcessId", "DelayedAutoStart",
               "BinaryPermissionsStr", "Hostname", "SystemGroup", "Location", "Label"]

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
            if col == 13:
                worksheet.write(row, col, str(c), cell_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:N1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output


def generate_services_acl_excel(acls=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for a in acls:
        h = a.Service.Host
        tmp = [h.Hostname, h.SystemGroup, h.Location, h.Label, a.Name, a.AccountName, a.AccessControlType, a.AccessRight,
               a.Service.StartName, a.Service.PathName, a.Service.StartMode ]
        rows.append(tmp)


    header_data = ["Hostname", "SystemGroup", "Location", "Label", "Name", "AccountName", "AccessControlType", "AccessRight",
                   "StartName", "Path", "Startmode" ]

    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    wrap_format = workbook.add_format({'text_wrap': True})

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for r in rows:
        for c in r:
            if col == 6:
                worksheet.write(row, col, str(c), wrap_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:G1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
