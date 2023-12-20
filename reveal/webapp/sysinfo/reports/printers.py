from flask import render_template, Response, url_for, request
from flask_login import login_required

from reveal.webapp.sysinfo import sysinfo_bp
from reveal.core.models.sysinfo import Host
from reveal.core.export.excel.printer import generate_printer_excel_brief
from reveal.webapi.querries.printers import get_hosts_by_printers, FILE_PRINTER_LIST
from reveal.core.reports import ReportInfo
from reveal.webapp.sysinfo.forms.report.PrinterReport import FilePrinterReportForm


####################################################################
# List printers and corresponding hosts
####################################################################
@sysinfo_bp.route('/report/filerprinter/', methods=['GET', 'POST'])
@login_required
def hosts_report_fileprinter():
    printer_filter = FILE_PRINTER_LIST
    host_filter = []

    form = FilePrinterReportForm()

    if request.method == 'POST':

        if form.validate_on_submit():
            systemgroup = form.SystemGroup.data
            location = form.Location.data

            invertSystemgroup = form.InvertSystemGroup.data
            invertLocation = form.InvertLocation.data

            if len(systemgroup) > 0:
                if not invertSystemgroup:
                    host_filter.append(Host.SystemGroup.ilike("%" + systemgroup + "%"))
                else:
                    host_filter.append(Host.SystemGroup.notilike("%" + systemgroup + "%"))
            if len(location) > 0:
                if not invertLocation:
                    host_filter.append(Host.Location.ilike("%" + location + "%"))
                else:
                    host_filter.append(Host.Location.notilike("%" + location + "%"))

            printer_matches = get_hosts_by_printers(printer_filter=printer_filter, host_filter=host_filter)

            if 'excel' in request.form:
                output = generate_printer_excel_brief(printer_matches=printer_matches)
                return Response(output, mimetype="text/docx",
                                headers={"Content-disposition": "attachment; filename=printer-hosts-matches-brief.xlsx",
                                         "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

    else:
        printer_matches = get_hosts_by_printers(printer_filter=printer_filter, host_filter=host_filter)
    return render_template('sysinfo/reports/printer_hosts_list.html', printer_matches=printer_matches, form=form,
                           report_name="File Printer Installed")



class ReportFilePrinterInstalled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="File Printer Installed",
            category="HMI Hardening",
            tags=["Systemhardening", "Print to PDF", "PDFCreator", "XPS Printer", "Send to OneNote"],
            description='Report all hosts which have a file printer installed',
            views=[("view", url_for("sysinfo.hosts_report_fileprinter"))]
        )