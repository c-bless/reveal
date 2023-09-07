
from io import BytesIO

import xlsxwriter


def generate_configchecks_excel(checks=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for c in checks:

        tmp = [c.Name, c.Component, c.Method, c.Key, c.Value, c.Result, c.Message, c.Host.Hostname, c.Host.SystemGroup, c.Host.Location]
        rows.append(tmp)


    header_data = ["Name", "Component", "Method", "Key", "Value", "Result", "Message", "Hostname", "Systemgroup", "Location"]

    wrap_format = workbook.add_format({'text_wrap': True})
    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for host in rows:
        for c in host:
            worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    worksheet.autofilter("A1:J1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output


def generate_registrychecks_excel(checks=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for c in checks:
        tmp = [c.Name, c.Category, c.Tags, c.Path, c.Key, c.Expected, c.Description, c.KeyExists, c.ValueMatch, c.CurrentValue, c.Host.Hostname, c.Host.SystemGroup, c.Host.Location, c.Host.Whoami, c.Host.WhoamiIsAdmin]
        rows.append(tmp)


    header_data = ["Name", "Category", "Tags", "Path", "Key", "Expected", "Description", "KeyExists", "ValueMatch", "CurrentValue", "Hostname", "Systemgroup", "Location", "Whoami", "Whoami is Admin"]

    wrap_format = workbook.add_format({'text_wrap': True})
    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for host in rows:
        for c in host:
            worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    worksheet.autofilter("A1:M1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
