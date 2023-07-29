from io import BytesIO

import xlsxwriter


def generate_userassignment_excel(members=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for m in members:
        host, group, caption = m
        tmp = [host, group, caption]
        rows.append(tmp)


    header_data = ["Host", "Group", "Caption"]

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

    worksheet.autofilter("A1:C1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
