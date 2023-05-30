
import os
from docxtpl import DocxTemplate, RichText
import xlsxwriter
from io import StringIO, BytesIO

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../.."))
template_dir = "{0}/reports/templates/hosts/".format(basedir)
template_detail_dir = "{0}/reports/templates/details/".format(basedir)
report_dir = "{0}/reports/outdir/".format(basedir)


def generate_hosts_docx(template, hosts=[]):
    doc = DocxTemplate(template)
    context = {'hosts': hosts}
    doc.render(context)
    f = BytesIO()
    doc.save(f)
    length = f.tell()
    f.seek(0)
    return f


def generate_single_host_docx(template, host=None):
    doc = DocxTemplate(template)
    context = {'host': host}
    doc.render(context)
    f = BytesIO()
    doc.save(f)
    length = f.tell()
    f.seek(0)
    return f


def generate_hosts_excel(hosts=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for h in hosts:
        ips = []
        products = []
        users = []
        admins = []
        rdp = []
        groups = []
        hotfixes = []
        for i in h.NetIPAddresses:
            ips.append("{0}/{1} ({2})".format(i.IP, i.Prefix, i.InterfaceAlias))
        if len(ips) == 0: ips.append("")
        for p in h.Products:
            products.append("{0} ({1})".format(p.Name, p.Version))
        if len(products) == 0: products.append("")
        for u in h.Users:
            users.append("{0}\\{1} (Disabled: {2}, PW required: {3})".format(u.Domain, u.Name, u.Disabled, u.PasswordRequired))
        if len(users) == 0: users.append("")
        for hf in h.Hotfixes:
            hotfixes.append("{0} ({1})".format(hf.HotfixId, hf.InstalledOn))
        if len(hotfixes) == 0: hotfixes.append("")
        for g in h.Groups:
            name = g.Name
            members =[]
            for m in g.Members:
                members.append(str(m.Caption))
            if len(members) == 0:
                members.append("")
            else:
                outstr = "{0}: ({1})".format(name, ", ".join(members))
                groups.append(outstr)
            if g.SID == "S-1-5-32-544":
                admins.append("\n".join(members))
            if g.SID == "S-1-5-32-555":
                rdp.append("\n".join(members))
        tmp = [h.SystemGroup, h.Location, h.Hostname, h.Domain, h.DomainRole, h.OSName, h.OSVersion, h.OSBuildNumber, "\n".join(ips),
               "\n".join(users),  "\n".join(groups), "\n".join(admins), "\n".join(rdp), "\n".join(products),
               "\n".join(hotfixes), h.OSInstallDate, h.OSProductType, h.LogonServer, h.TimeZone, h.KeyboardLayout,
               h.HyperVisorPresent, h.DeviceGuardSmartStatus, h.PSVersion,
               h.AutoAdminLogon, h.ForceAutoLogon, h.DefaultPassword, h.DefaultUserName, h.PS2Installed]
        rows.append(tmp)


    header_data = ["Systemgroup", "Location", "Hostname", "Domain", "DomainRole", "OSName", "OSVersion", "OSBuildNumber", "IPs", "Users",
                   "Groups with members", "Admins", "RDP Users", "Products", "hotfixes", "OSInstallDate",
                   "OSProductType", "LogonServer", "TimeZone", "KeyboardLayout",
                   "HyperVisorPresent", "DeviceGuardSmartStatus", "PSVersion", "AutoAdminLogon", "ForceAutoLogon",
                   "DefaultPassword", "DefaultUserName","PS2Installed"]

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
    for host in (rows):
        for c in host:
            if ( col > 7) and (col <= 14):
                worksheet.write(row, col, str(c), wrap_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:X1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output


def generate_services_excel(services=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for s in services:
        tmp = [s.SystemName, s.Caption, s.Description, s.Name, s.StartMode, s.PathName, s.Started, s.StartName,
               s.DisplayName, s.Running, s.AcceptStop, s.AcceptPause, s.ProcessId, s.DelayedAutoStart,
               s.BinaryPermissionsStr]
        rows.append(tmp)


    header_data = ["SystemName", "Caption", "Description", "Name", "StartMode", "PathName", "Started", "StartName",
               "DisplayName", "Running", "AcceptStop", "AcceptPause", "ProcessId", "DelayedAutoStart",
               "BinaryPermissionsStr"]

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
    for service in (rows):
        for c in service:
            if (col == 14):
                worksheet.write(row, col, str(c), cell_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:O1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output



def generate_products_excel(products=[]):
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    worksheet = workbook.add_worksheet()

    rows = []

    for p in products:
        tmp = [ p.Caption, p.Name, p.Version, p.Host_id, p.InstallLocation, p.InstallDate]
        rows.append(tmp)


    header_data = ["Caption", "Name", "Version", "Host_id", "InstallLocation", "InstallDate"]

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
    for service in (rows):
        for c in service:
            worksheet.write(row, col, str(c))
            col += 1
        worksheet.autofilter("A1:O1")
        col = 0
        row += 1

    worksheet.autofit()
    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output