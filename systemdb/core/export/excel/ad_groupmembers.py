from io import BytesIO

import xlsxwriter


def generate_ad_groupmembers_excel(groups=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    header_data = ["SAMAccountName", "Domain", "GroupCategory", "GroupScope", "SID", "Members"]

    for g in groups:
        members = []
        for m in g.Members:
            members.append("{0}\{1}".format(m.Group.Domain, m.SamAccountName))

        tmp = [g.SamAccountName, g.Domain, g.GroupCategory, g.GroupScope, g.SID, "\n".join(members)]
        rows.append(tmp)

    wrap_format = workbook.add_format({'text_wrap': True})
    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    row = 1
    col = 0
    for h in rows:
        for c in h:
            if c == 5:
                worksheet.write(row, col, str(c), wrap_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    worksheet.autofilter("A1:F1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output

