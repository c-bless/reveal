from io import BytesIO

import xlsxwriter


def generate_eol_excel_brief(eol_matches=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    header_data = ["OS", "Version", "OSVersion", "Build", "ServiceOption", "StartDate", "EndOfService",
                   "MainstreamEndDate", "Hosts / Systemgroup / Location / Label", ]

    wrap_format = workbook.add_format({'text_wrap': True})
    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    row = 1
    for m in eol_matches:
        e = m.Eol
        hosts = m.Hosts
        if len(hosts) == 0:
            continue
        worksheet.write(row, 0, str(e.OS))
        worksheet.write(row, 1, str(e.Version))
        worksheet.write(row, 2, str(e.OSVersion))
        worksheet.write(row, 3, str(e.Build))
        worksheet.write(row, 4, str(e.ServiceOption))
        worksheet.write(row, 5, str(e.StartDate))
        worksheet.write(row, 6, str(e.EndOfService))
        worksheet.write(row, 7, str(e.MainstreamEndDate))
        host_list = []
        for h in hosts:
            host_list.append("{0} / {1} / {2} / {3}".format(h.Hostname, h.SystemGroup, h.Location, h.Label))
        worksheet.write(row, 8, "\n".join(host_list), wrap_format)
        row += 1

    worksheet.autofilter("A1:I1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output



def generate_eol_excel_full(eol_matches=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    header_data = ["OS", "Version", "OSVersion", "Build", "ServiceOption", "StartDate", "EndOfService",
                   "MainstreamEndDate", "Host", "HostOS", "SystemGroup", "Location", "Label"]

    wrap_format = workbook.add_format({'text_wrap': True})
    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    row = 1
    for m in eol_matches:
        e = m.Eol
        hosts = m.Hosts
        for h in hosts:
            worksheet.write(row, 0, str(e.OS))
            worksheet.write(row, 1, str(e.Version))
            worksheet.write(row, 2, str(e.OSVersion))
            worksheet.write(row, 3, str(e.Build))
            worksheet.write(row, 4, str(e.ServiceOption))
            worksheet.write(row, 5, str(e.StartDate))
            worksheet.write(row, 6, str(e.EndOfService))
            worksheet.write(row, 7, str(e.MainstreamEndDate))
            worksheet.write(row, 8, str(h.Hostname))
            worksheet.write(row, 9, str(h.OSVersion))
            worksheet.write(row, 10, str(h.SystemGroup))
            worksheet.write(row, 11, str(h.Location))
            worksheet.write(row, 12, str(h.Label))
            row += 1

    worksheet.autofilter("A1:M1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output

