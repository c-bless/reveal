from http import HTTPStatus
import datetime

from reveal.core.models.sysinfo import Host
from reveal.core.querries.updates import get_EoLInfo

from reveal.webapi.sysinfo.reportviews import report_bp
from reveal.webapi.extentions import auth

from reveal.webapi.tags import T_REPORT_SYSINFO
from reveal.webapi.tags import T_GENERAL_HARDENING
from reveal.webapi.tags import T_PATCH_LIFECYCLE_MGMT

from reveal.webapi.sysinfo.schemas.responses.hosts import HostSchema
from reveal.webapi.sysinfo.schemas.responses.eol import EoLMatchSchema

from reveal.core.models.eol import EoL
from reveal.webapi.sysinfo.schemas.responses.eol import EoLSchema

#####################################################################################
# Matching host and End-of-Life entries
#####################################################################################
@report_bp.get("/wsus-http/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns a list of hosts configured to use WSUS via http.",
                summary="Find all hosts configured for using WSUS vi http.",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=HostSchema(many=True))
def report_wsus_via_http():
    return Host.query.filter(Host.WUServer.like('http://%'))


#####################################################################################
# Matching host and End-of-Life entries
#####################################################################################
@report_bp.get("/eol/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns the a list of end-of-life hosts",
                summary="Find all end-of-life hosts",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_PATCH_LIFECYCLE_MGMT])
@report_bp.output(status_code=HTTPStatus.OK,
                  schema=EoLMatchSchema(many=True))
def report_eol_hosts():
    eol_matches = get_EoLInfo()
    return eol_matches


#####################################################################################
# Last update > n days
#####################################################################################
@report_bp.get("/LastUpdate/<int:days>")
@report_bp.auth_required(auth)
@report_bp.doc( description="Returns the hosts which have not been updated for a specified amount of days.",
                summary="Find all hosts which have not been updated for a specified amount of days.",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_PATCH_LIFECYCLE_MGMT])
@report_bp.output(status_code=HTTPStatus.OK.value,
                  schema=HostSchema(many=True))
def report_last_update(days):
    now = datetime.datetime.now()
    delta = now - datetime.timedelta(days=days)
    return Host.query.filter(Host.LastUpdate <= delta).all()



@report_bp.get("/eol-dates/")
@report_bp.auth_required(auth)
@report_bp.doc( description="Return a list end-of-life dates",
                summary="Find all end-of-life dates",
                security='ApiKeyAuth',
                tags=[T_REPORT_SYSINFO, T_GENERAL_HARDENING, T_PATCH_LIFECYCLE_MGMT])
@report_bp.output(status_code=HTTPStatus.OK.value, schema=EoLSchema(many=True))
def get():
    return EoL.query.all()
