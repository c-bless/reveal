
from io import BytesIO

import xlsxwriter

from reveal.core.sids import SID_LOCAL_ADMIN_GROUP
from reveal.core.sids import SID_BUILTIN_REMOTE_DESKTOP_USERS

def generate_winlogon_excel(hosts=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for h in hosts:

        tmp = [h.SystemGroup, h.Location, h.Hostname, h.AutoAdminLogon, h.ForceAutoLogon,h.DefaultDomain, h.DefaultPassword, h.DefaultUserName]
        rows.append(tmp)


    header_data = ["Systemgroup", "Location", "Hostname", "AutoAdminLogon",
                   "ForceAutoLogon", "DefaultDomain", "DefaultPassword", "DefaultUserName"]

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

    worksheet.autofilter("A1:H1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output

