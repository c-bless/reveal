
import os
from docxtpl import DocxTemplate, RichText
import xlsxwriter
from io import StringIO, BytesIO

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../.."))
template_dir = "{0}/reports/templates/hosts/".format(basedir)
template_detail_dir = "{0}/reports/templates/details/".format(basedir)
report_dir = "{0}/reports/outdir/".format(basedir)


def generate_computer_excel(computer_list=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []
    cell_format = workbook.add_format({'text_wrap': True})

    for c in computer_list:
        spns = [ "{0}".format(s.Name) for s in c.SPNs]
        tmp = [c.DNSHostName, c.SamAccountName, c.Enabled, c.IPv4Address, c.IPv6Address, c.OperatingSystem,
               c.OperatingSystemVersion, c.SID, c.DistinguishedName, c.TrustedForDelegation, c.TrustedToAuthForDelegation,
               c.PrimaryGroup, c.primaryGroupID, c.pwdLastSet, c.ProtectedFromAccidentalDeletion, c.Description, "\n".join(spns)]
        rows.append(tmp)


    header_data = ["DNSHostName", "SamAccountName", "Enabled", "IPv4Address","IPv6Address", "OperatingSystem",
               "OperatingSystemVersion", "SID", "DistinguishedName", "TrustedForDelegation", "TrustedToAuthForDelegation",
               "PrimaryGroup", "primaryGroupID", "pwdLastSet", "ProtectedFromAccidentalDeletion", "Description", "SPNs"]

    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for r in (rows):
        for c in r:
            if col == 16:
                worksheet.write(row, col, str(c), cell_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:P1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output


def generate_user_excel(user_list=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []
    cell_format = workbook.add_format({'text_wrap': True})

    for u in user_list:
        memberships = [ "{0}".format(g.Group) for g in u.Memberships]
        tmp = [u.SAMAccountName, u.Name, u.GivenName, u.Surname, u.SID, u.Enabled, u.BadLogonCount, u.BadPwdCount,
               u.Created, u.LastBadPasswordAttempt, u.lastLogon, u.logonCount, u.PasswordExpired,  u.PasswordLastSet,
               u.Modified, u.MemberOfStr, "\n".join(memberships), u.Domain_id]
        rows.append(tmp)


    header_data = ["SamAccountName", "Name", "GivenName", "Surname", "SID", "Enabled", "BadLogonCount", "BadPwdCount",
                   "Created", "LastBadPasswordAttempt", "lastLogon", "logonCount", "PasswordExpired", "PasswordLastSet",
                   "Modified", "memberof", "memberships", "domain"]

    header_format = workbook.add_format({'bold': True,
                                         'bottom': 2,
                                         'bg_color': '#CCCCCC'})

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for r in (rows):
        for c in r:
            if col == 16:
                worksheet.write(row, col, str(c), cell_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:P1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
