from io import BytesIO

import xlsxwriter


def generate_ps2_installed(hosts=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    header_data = ["Hostname", "Domain", "SystemGroup", "Location", "OS Name", "OS Version", "OS BuildNumber",
                   "PS2Enabled", "PSActive", "PSInstalled"]

    for h in hosts:
        versions = []
        for v in h.PSInstalledVersions:
            versions.append(v.RuntimeVersion)
        tmp = [h.Hostname,  h.Domain, h.SystemGroup, h.Location, h.OSName, h.OSVersion, h.OSBuildNumber,
               h.PS2Installed, h.PSVersion, "\n".join(versions)]
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
            worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    worksheet.autofilter("A1:K1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output

