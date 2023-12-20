from reveal.core.models.sysinfo import Printer
from reveal.core.models.sysinfo import Host
from reveal.webapi.sysinfo.schemas.responses.hosts import PrinterMatchSchema

FILE_PRINTER_LIST = ["PDFCreator", " Microsoft OneNote", "Microsoft XPS", "Microsoft Print To PDF"]

def get_hosts_by_printers(printer_filter=[],host_filter =[]):
    results = []
    for f in printer_filter:
        printers = Printer.query.filter(Printer.Name.ilike(f'%{f}%')).join(Host).filter(*host_filter).all()
        printer_match = PrinterMatchSchema()
        printer_match.Printer = f
        hosts = []
        for p in printers:
            hosts.append(p.Host)
        printer_match.Hosts = hosts
        results.append(printer_match)
    return results