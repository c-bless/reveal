from flask import render_template, Response, url_for
import datetime

from .. import sysinfo_bp
from ..export_func import generate_printer_excel_brief, generate_printer_excel_full

from ...models.sysinfo import Host
from ...api.sysinfo.querries.printers import get_hosts_by_printers, FILE_PRINTER_LIST


####################################################################
# List printers and corresponding hosts
####################################################################

@sysinfo_bp.route('/hosts/report/filerprinter/', methods=['GET'])
def hosts_report_fileprinter():
    filters = FILE_PRINTER_LIST
    printer_matches = get_hosts_by_printers(filters=filters)
    return render_template('printer_hosts_list.html', printer_matches=printer_matches)

@sysinfo_bp.route('/hosts/report/filerprinter/excel/brief', methods=['GET'])
def hosts_report_filerprinter_excel_brief():
    filters = FILE_PRINTER_LIST
    printer_matches = get_hosts_by_printers(filters=filters)
    output = generate_printer_excel_brief(printer_matches=printer_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=printer-hosts-matches-brief.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})

@sysinfo_bp.route('/hosts/report/filerprinter/excel/full', methods=['GET'])
def hosts_report_filerprinter_excel_full():
    filters = FILE_PRINTER_LIST
    printer_matches = get_hosts_by_printers(filters=filters)
    output = generate_printer_excel_full(printer_matches=printer_matches)
    return Response(output, mimetype="text/docx",
                    headers={"Content-disposition": "attachment; filename=printer-hosts-matches-full.xlsx",
                             "Content-type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"})
