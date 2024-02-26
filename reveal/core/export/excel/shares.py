from io import BytesIO

import xlsxwriter


def generate_shares_excel(shares=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for s in shares:
        uri = "\\\\{0}\\{1}".format(s.Host, s.Name)
        uri2 = "\\\\{0}.{1}\\{2}".format(s.Host, s.Host.Domain, s.Name)
        share_acls = []
        for s_acl in s.SharePermissions:
            acl = "{0} / {1} / {2}".format(s_acl.AccountName, s_acl.AccessControlType, s_acl.AccessRight)
            share_acls.append(acl)
        ntfs_acls = []
        for ntfs in s.NTFSPermissions:
            acl = "{0} / {1} / {2}".format(ntfs.AccountName, ntfs.AccessControlType, ntfs.AccessRight)
            ntfs_acls.append(acl)
        tmp = [s.Name, s.Path, s.Description, s.Host, s.Host.SystemGroup, s.Host.Location, s.Host.Label, uri, uri2,
               "\n".join(share_acls), "\n".join(ntfs_acls)]
        rows.append(tmp)


    header_data = ["Name", "Path", "Description", "Hostname", "SystemGroup", "Location", "Label", "URI", "URI (with domain)",
                   "Share ACLs", "NTFS ACLs"]

    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})
    wrap_format = workbook.add_format({'text_wrap': True})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for service in rows:
        for c in service:
            if col > 7:
                worksheet.write(row, col, str(c), wrap_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:J1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
