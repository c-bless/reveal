from io import BytesIO

import xlsxwriter


def generate_printer_excel_brief(printer_matches=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    header_data = ["Printer Query String", "Hosts / Systemgroup / Location"]

    wrap_format = workbook.add_format({'text_wrap': True})
    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    row = 1
    for m in printer_matches:
        hosts = m.Hosts
        if len(hosts) == 0:
            continue
        worksheet.write(row, 0, str(m.Printer))
        host_list = []
        for h in hosts:
            host_list.append("{0} / {1} / {2}".format(h.Hostname, h.SystemGroup, h.Location))
        worksheet.write(row, 1, "\n".join(host_list), wrap_format)
        row += 1

    worksheet.autofilter("A1:B1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output

