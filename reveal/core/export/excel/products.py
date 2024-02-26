
from io import BytesIO

import xlsxwriter


def generate_products_excel(products=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for p in products:
        tmp = [ p.Caption, p.Name, p.Version, p.Host_id, p.Host, p.Host.SystemGroup, p.Host.Location, p.Host.Label, p.InstallLocation, p.InstallDate]
        rows.append(tmp)


    header_data = ["Caption", "Name", "Version", "Host_id","Host", "SystemGroup", "Location", "Label", "InstallLocation", "InstallDate"]

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

    worksheet.autofilter("A1:G1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
