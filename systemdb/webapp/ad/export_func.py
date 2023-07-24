import os
import xlsxwriter
from io import BytesIO

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../.."))
template_dir = "{0}/reports/templates/sysinfo/".format(basedir)
template_detail_dir = "{0}/reports/templates/details/".format(basedir)
report_dir = "{0}/reports/outdir/".format(basedir)

header_format_dict = {'bold': True, 'bottom': 2, 'bg_color': '#CCCCCC'}
wrap_format_dict = {'text_wrap': True}
bold_format_dict = {'bold': True}

def generate_computer_excel(computer_list=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})

    create_computer_worksheet(workbook=workbook,computer_list=computer_list)
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output


def generate_user_excel(user_list=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})

    create_user_worksheet(workbook=workbook, user_list=user_list)
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output


def create_user_worksheet(workbook, user_list=[]):
    worksheet = workbook.add_worksheet("User")

    header_data = ["SamAccountName", "Name", "GivenName", "Surname", "SID", "Enabled", "BadLogonCount", "BadPwdCount",
                   "Created", "LastBadPasswordAttempt", "lastLogon", "logonCount", "PasswordExpired", "PasswordLastSet",
                   "Modified", "memberof", "memberships", "views"]

    header_format = workbook.add_format(header_format_dict)
    wrap_format = workbook.add_format(wrap_format_dict)

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    rows = []
    for u in user_list:
        memberships = ["{0}".format(g.Group) for g in u.Memberships]
        membershipStr = "\n".join(memberships)
        tmp = [u.SAMAccountName, u.Name, u.GivenName, u.Surname, u.SID, u.Enabled, u.BadLogonCount, u.BadPwdCount,
               u.Created, u.LastBadPasswordAttempt, u.lastLogon, u.logonCount, u.PasswordExpired, u.PasswordLastSet,
               u.Modified, u.MemberOfStr, membershipStr, u.Domain_id]
        rows.append(tmp)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for r in rows:
        for c in r:
            if col == 16:
                worksheet.write(row, col, str(c), wrap_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:P1")
        col = 0
        row += 1

    worksheet.autofit()
    return worksheet


def create_computer_worksheet(workbook, computer_list=[]):
    worksheet = workbook.add_worksheet("Computer")

    header_format = workbook.add_format(header_format_dict)
    wrap_format = workbook.add_format(wrap_format_dict)

    header_data = ["DNSHostName", "SamAccountName", "Enabled", "IPv4Address", "IPv6Address", "OperatingSystem",
                   "OperatingSystemVersion", "SID", "DistinguishedName", "TrustedForDelegation",
                   "TrustedToAuthForDelegation",
                   "PrimaryGroup", "primaryGroupID", "pwdLastSet", "ProtectedFromAccidentalDeletion", "Description",
                   "SPNs"]

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    rows = []

    for c in computer_list:
        spns = ["{0}".format(s.Name) for s in c.SPNs]
        tmp = [c.DNSHostName, c.SamAccountName, c.Enabled, c.IPv4Address, c.IPv6Address, c.OperatingSystem,
               c.OperatingSystemVersion, c.SID, c.DistinguishedName, c.TrustedForDelegation,
               c.TrustedToAuthForDelegation,
               c.PrimaryGroup, c.primaryGroupID, c.pwdLastSet, c.ProtectedFromAccidentalDeletion, c.Description,
               "\n".join(spns)]
        rows.append(tmp)


    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for r in rows:
        for c in r:
            if col == 16:
                worksheet.write(row, col, str(c), wrap_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:Q1")
        col = 0
        row += 1

    worksheet.autofit()
    return worksheet


def create_domain_worksheet(workbook, domain, policy_list=[]):
    worksheet = workbook.add_worksheet("Domain")

    header_format = workbook.add_format({ "bold": 1, "align": "center", 'bg_color': '#CCCCCC'})
    bold_format = workbook.add_format(bold_format_dict)

    worksheet.merge_range("A1:B1", "General Information", header_format)

    rows = []
    rows.append(["Name", domain.Name])
    rows.append(["NetBIOSName", domain.NetBIOSName])
    rows.append(["DomainSID", domain.DomainSID])
    rows.append(["DistinguishedName", domain.DistinguishedName])
    rows.append(["DNSRoot", domain.DNSRoot])
    rows.append(["RIDMaster", domain.RIDMaster])
    rows.append(["PDCEmulator", domain.PDCEmulator])
    rows.append(["ParentDomain", domain.ParentDomain])
    rows.append(["Forest", domain.Forest])
    rows.append(["UsersContainer", domain.UsersContainer])
    rows.append(["SystemContainer", domain.SystemContainer])
    rows.append(["ComputerContainer", domain.ComputerContainer])
    rows.append(["InfrastructureMaster", domain.InfrastructureMaster])

    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    # Iterate over the data and write it out row by row.
    for r in rows:
        header , value = r
        worksheet.write(row, 0, str(header), bold_format)
        worksheet.write(row, 1 , str(value))
        row += 1


    header_format = workbook.add_format(header_format_dict)
    wrap_format = workbook.add_format(wrap_format_dict)

    header_data = ["Type", "Name", "ComplexityEnabled", "DistinguishedName", "LockoutDuration", "LockoutObservationWindow",
                   "LockoutThreshold", "MaxPasswordAge", "MinPasswordAge", "MinPasswordLength",
                   "PasswordHistoryCount", "ReversibleEncryptionEnabled"]

    for col_num, data in enumerate(header_data):
        worksheet.write(20, col_num, data, header_format)

    rows = []

    for c in policy_list:
        tmp = [c.Type, c.Name, c.ComplexityEnabled, c.DistinguishedName, c.LockoutDuration, c.LockoutObservationWindow,
               c.LockoutThreshold, c.MaxPasswordAge, c.MinPasswordAge, c.MinPasswordLength,
               c.PasswordHistoryCount, c.ReversibleEncryptionEnabled]
        rows.append(tmp)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 21
    col = 0
    # Iterate over the data and write it out row by row.
    for r in rows:
        for c in r:
            worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    worksheet.autofit()
    return worksheet



def create_dc_worksheet(workbook, dc_list=[]):
    worksheet = workbook.add_worksheet("DCs")

    header_format = workbook.add_format(header_format_dict)
    wrap_format = workbook.add_format(wrap_format_dict)

    header_data = ["Name", "Hostname", "Enabled", "IPv4Address", "IPv6Address", "OperatingSystem",
                   "Domain", "Forest", "IsGlobalCatalog", "IsReadOnly", "LdapPort", "SslPort", "ServerRoles"]

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    rows = []

    for c in dc_list:
        ServerRoles = ["{0}".format(s.Role) for s in c.ServerRoles]
        tmp = [c.Name, c.Hostname, c.Enabled, c.IPv4Address, c.IPv6Address, c.OperatingSystem,
               c.Domain, c.Forest, c.IsGlobalCatalog, c.IsReadOnly, c.LdapPort, c.SslPort, "\n".join(ServerRoles)]
        rows.append(tmp)


    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for r in rows:
        for c in r:
            if col == 12:
                worksheet.write(row, col, str(c), wrap_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:M1")
        col = 0
        row += 1

    worksheet.autofit()
    return worksheet


def create_trust_worksheet(workbook, trust_list=[]):
    worksheet = workbook.add_worksheet("Trusts")

    header_format = workbook.add_format(header_format_dict)
    wrap_format = workbook.add_format(wrap_format_dict)

    header_data = ["Source", "Target", "Direction", "UplevelOnly", "UsesAESKeys", "UsesRC4Encryption",
                   "TGTDelegation", "SIDFilteringForestAware", "SIDFilteringQuarantined", "SelectiveAuthentication",
                   "DisallowTransivity", "DistinguishedName", "ForestTransitive", "IntraForest", "IsTreeParent",
                   "IsTreeRoot"]

    for col_num, data in enumerate(header_data):
        worksheet.write(0, col_num, data, header_format)

    rows = []

    for c in trust_list:
        tmp = [c.Source, c.Target, c.Direction, c.UplevelOnly, c.UsesAESKeys, c.UsesRC4Encryption,
               c.TGTDelegation, c.SIDFilteringForestAware, c.SIDFilteringQuarantined, c.SelectiveAuthentication,
               c.DisallowTransivity, c.ForestTransitive, c.IntraForest, c.IsTreeParent, c.IsTreeRoot]
        rows.append(tmp)


    # Start from the first cell. Rows and columns are zero indexed.
    row = 1
    col = 0
    # Iterate over the data and write it out row by row.
    for r in rows:
        for c in r:
            worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:P1")
        col = 0
        row += 1

    worksheet.autofit()
    return worksheet




def generate_domain_excel(domain, user_list=[], computer_list=[], dc_list=[], trust_list=[], policy_list=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})

    domain_worksheet = create_domain_worksheet(workbook=workbook, domain=domain, policy_list=policy_list)
    user_worksheet = create_user_worksheet(workbook=workbook, user_list=user_list)
    computer_worksheet= create_computer_worksheet(workbook=workbook, computer_list=computer_list)
    trust_worksheet = create_trust_worksheet(workbook=workbook, trust_list=trust_list)
    dc_worksheet = create_dc_worksheet(workbook=workbook, dc_list=dc_list)

    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
