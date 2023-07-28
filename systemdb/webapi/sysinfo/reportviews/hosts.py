from http import HTTPStatus
from apiflask import HTTPError

from systemdb.core.models.sysinfo import Host
from systemdb.webapi.querries.printers import get_hosts_by_printers, FILE_PRINTER_LIST

from systemdb.webapi.sysinfo.reportviews import report_bp as bp
from systemdb.webapi.extentions import auth


from systemdb.webapi.sysinfo.schemas.arguments.printers import PrinterMatchSearchSchema
from systemdb.webapi.sysinfo.schemas.responses.hosts import HostSchema
from systemdb.webapi.sysinfo.schemas.responses.printers import PrinterMatchSchema


from systemdb.webapi.tags import T_GENERAL_HARDENING
from systemdb.webapi.tags import T_SISYPHUS
from systemdb.webapi.tags import T_REPORT_SYSINFO
from systemdb.webapi.tags import T_HMI_HARDENING


#####################################################################################
# Hosts with PowerShell version 2.0
#####################################################################################
@bp.get("/PS2/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=HostSchema(many=True))
@bp.doc(description="Returns the hosts with PowerShell version 2.0 installed.",
        summary="Find all hosts with PowerShell version 2.0 installed.",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_SISYPHUS])
def report_PS2():
    return Host.query.filter(Host.PS2Installed == True).all()


#####################################################################################
# Hosts with SMBv1 enabled
#####################################################################################
@bp.get("/SMBv1/")
@bp.auth_required(auth)
@bp.doc(description="Returns the hosts with SMBv1 enabled.",
        summary="Find all hosts with SMBv1 enabled.",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING])
@bp.output(status_code=HTTPStatus.OK,
           schema=HostSchema(many=True))
def report_smbv1():
    return Host.query.filter(Host.SMBv1Enabled == True).all()


#####################################################################################
# Hosts with WSH enabled
#####################################################################################
@bp.get("/WSH-enabled/")
@bp.auth_required(auth)
@bp.doc(description="Returns the hosts with WSH enabled.",
        summary="Find all hosts with WSH enabled.",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_SISYPHUS])
@bp.output(status_code=HTTPStatus.OK,
           schema=HostSchema(many=True))
def report_wsh_enabled():
    return Host.query.filter(Host.WSHEnabled == True).all()

#####################################################################################
# Hosts with WSH remote enabled
#####################################################################################
@bp.get("/WSH-remote/")
@bp.auth_required(auth)
@bp.doc(description="Returns the hosts with WSH remote enabled.",
        summary="Find all hosts with WSH remote enabled.",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_SISYPHUS])
@bp.output(status_code=HTTPStatus.OK,
           schema=HostSchema(many=True))
def report_wsh_remote_enabled():
    return Host.query.filter(Host.WSHRemote == True).all()





#####################################################################################
# Winlogon with password
#####################################################################################
@bp.get("/Winlogon/")
@bp.auth_required(auth)
@bp.doc(description="Returns the hosts which have the autologon password (DefaultPassword) in Winlogon Hive.",
        summary="Find all hosts with DefaultPassword in Winlogon hive",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_HMI_HARDENING])
@bp.output(status_code=HTTPStatus.OK, schema=HostSchema(many=True))
def report_winlogon():
    return Host.query.filter(Host.DefaultPassword != "").all()


#####################################################################################
# Display Hosts with installed file printers
#####################################################################################
@bp.get("/fileprinter/")
@bp.auth_required(auth)
@bp.doc(description="Return a list of file printers and corresponding hosts having this printer installed.",
         summary="Find a list of file printers and corresponding hosts having this printer installed.",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_HMI_HARDENING])
@bp.output(status_code=HTTPStatus.OK, schema=PrinterMatchSchema(many=True))
def report_file_printer():
    filters = FILE_PRINTER_LIST
    results = get_hosts_by_printers(filters=filters)
    return results


@bp.route("/printer/")
@bp.auth_required(auth)
@bp.input(PrinterMatchSearchSchema)
@bp.doc(description="Returns a list of printer and hosts that match the specified search query.",
        summary="Find a list of printer and hosts that match the specified search query.",
        security='ApiKeyAuth',
        tags=[T_REPORT_SYSINFO, T_HMI_HARDENING])
@bp.output(status_code=HTTPStatus.OK, schema=PrinterMatchSchema(many=True))
def report_printer(filters):
    errors = PrinterMatchSearchSchema().validate(filters)
    if errors:
        return HTTPError(HTTPStatus.BAD_REQUEST, str(errors))
    results = get_hosts_by_printers(filters=filters['names'])
    return results