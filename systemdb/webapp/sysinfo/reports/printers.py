from flask import render_template, Response, url_for
from flask_login import login_required

from systemdb.webapp.sysinfo import sysinfo_bp
from systemdb.webapp.sysinfo.export_func import generate_printer_excel_brief, generate_printer_excel_full
from systemdb.core.querries.printers import get_hosts_by_printers, FILE_PRINTER_LIST
from systemdb.webapp.sysinfo.reports import ReportInfo

####################################################################
# List printers and corresponding hosts
####################################################################

@sysinfo_bp.route('/report/filerprinter/', methods=['GET'])
@login_required
def hosts_report_fileprinter():
    filters = FILE_PRINTER_LIST
    printer_matches = get_hosts_by_printers(filters=filters)
    return render_template('printer_hosts_list.html', printer_matches=printer_matches)


@sysinfo_bp.route('/report/filerprinter/excel/brief', methods=['GET'])
@login_required
def hosts_report_filerprinter_excel_brief():
    filters = FILE_PRINTER_LIST
    printer_matches = get_hosts_by_printers(filters=filters)
    output = generate_printer_excel_brief(printer_matches=printer_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=printer-hosts-matches-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


@sysinfo_bp.route('/report/filerprinter/excel/full', methods=['GET'])
@login_required
def hosts_report_filerprinter_excel_full():
    filters = FILE_PRINTER_LIST
    printer_matches = get_hosts_by_printers(filters=filters)
    output = generate_printer_excel_full(printer_matches=printer_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=printer-hosts-matches-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})


class ReportFilePrinterInstalled(ReportInfo):

    def __init__(self):
        super().initWithParams(
            name="File Printer Installed",
            category="HMI Hardening",
            tags=["Systemhardening", "Print to PDF", "PDFCreator", "XPS Printer", "Send to OneNote"],
            description='Report all hosts which have a file printer installed',
            views=[("view", url_for("sysinfo.hosts_report_fileprinter"))]
        )