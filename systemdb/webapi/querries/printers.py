from systemdb.core.models.sysinfo import Printer
from systemdb.webapi.sysinfo.schemas.responses.hosts import PrinterMatchSchema

FILE_PRINTER_LIST = ["PDFCreator", " Microsoft OneNote", "Microsoft XPS", "Microsoft Print To PDF"]

def get_hosts_by_printers(filters=[]):
    results = []
    for f in filters:
        printers = Printer.query.filter(Printer.Name.ilike(f'%{f}%'))
        printer_match = PrinterMatchSchema()
        printer_match.Printer = f
        hosts = []
        for p in printers:
            hosts.append(p.Host)
        printer_match.Hosts = hosts
        results.append(printer_match)
    return results