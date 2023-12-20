from io import BytesIO

import xlsxwriter


def generate_group_members_excel(groups=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for g in groups:
        name = g.Name
        members = []
        for m in g.Members:
            members.append(str(m.Caption))
        if len(members) == 0:
            members.append("")
        host = g.Host.Hostname
        systemgroup = g.Host.SystemGroup
        location = g.Host.Location
        tmp = [host, systemgroup, location, name, g.SID, "\n".join(members)]
        rows.append(tmp)

    header_data = ["Host", "Systemgroup", "Location", "Group", "SID", "Members"]

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
            if col == 5:
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


def generate_localuser_excel(users=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for u in users:
        accountType = u.AccountType
        domain = u.Domain
        disabled = u.Disabled
        localAccount = u.LocalAccount
        name = u.Name
        fullName = u.FullName
        sid = u.SID
        lockout = u.Lockout
        pwchanged = u.PasswordChanged
        pwrequired = u.PasswordRequired
        description = u.Description
        host = u.Host.Hostname
        systemgroup = u.Host.SystemGroup
        location = u.Host.Location
        tmp = [accountType, domain, disabled, localAccount, name, fullName, sid, lockout, pwchanged, pwrequired,
               description, host, systemgroup, location]
        rows.append(tmp)

    header_data = ["AccountType", "Domain", "Disabled", "LocalAccount", "Name", "FullName", "SID", "Lockout",
                   "PasswordChanged", "PasswordRequired", "Description", "Host", "Systemgroup", "Location"]

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

    worksheet.autofilter("A1:N1")
    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
