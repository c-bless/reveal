
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

    rows = [
        ["Hostname", "Domain", "DomainRole", "IPs", "Users", "OSVersion", "OSBuildNumber", "OSName", "OSInstallDate",
         "OSProductType", "Products", "LogonServer", "TimeZone", "KeyboardLayout", "HyperVisorPresent",
         "DeviceGuardSmartStatus", "PSVersion", "AutoAdminLogon", "ForceAutoLogon", "DefaultPassword",
         "DefaultUserName"]
    ]

    for h in hosts:
        ips = []
        products = []
        users = []
        admins = []
        rdp = []
        cell_format = workbook.add_format({'text_wrap': True})
        for i in h.NetIPAddresses:
            ips.append("{0}/{1} ({2})".format(i.IP, i.Prefix, i.InterfaceAlias))
        for p in h.Products:
            products.append("{0} ({1})".format(p.Name, p.Version))
        for u in h.Users:
            users.append("{0}\\{1} (Disabled: {2}, PW required: {3})".format(u.Domain, u.Name, u.Disabled, u.PasswordRequired))
        for g in h.Groups:
            pass
        tmp = [h.Hostname, h.Domain, h.DomainRole, "\n".join(ips), "\n".join(users), h.OSVersion, h.OSBuildNumber, h.OSName, h.OSInstallDate,
               h.OSProductType, "\n".join(products),
               h.LogonServer, h.TimeZone, h.KeyboardLayout, h.HyperVisorPresent, h.DeviceGuardSmartStatus, h.PSVersion,
               h.AutoAdminLogon, h.ForceAutoLogon, h.DefaultPassword, h.DefaultUserName]
        rows.append(tmp)

    # Start from the first cell. Rows and columns are zero indexed.
    row = 0
    col = 0
    # Iterate over the data and write it out row by row.
    for host in (rows):
        for c in host:
            if ( col == 3) or (col == 4) or (col == 10):
                worksheet.write(row, col, str(c), cell_format)
            else:
                worksheet.write(row, col, str(c))
            col += 1
        col = 0
        row += 1

    # Close the workbook before streaming the data.
    workbook.close()

    # Rewind the buffer.
    output.seek(0)
    return output
