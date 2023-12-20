from http import HTTPStatus

from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import User
from reveal.core.models.sysinfo import Group
from reveal.core.models.sysinfo import Product
from reveal.core.models.sysinfo import Hotfix
from reveal.core.models.sysinfo import NetIPAddress
from reveal.core.models.sysinfo import NetAdapter
from reveal.core.models.sysinfo import Printer
from reveal.core.models.sysinfo import PSInstalledVersions

from reveal.webapi.sysinfo.views import bp
from reveal.webapi.extentions import auth

from reveal.webapi.sysinfo.schemas.responses.hosts import HostSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import UserSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import GroupSchema
from reveal.webapi.sysinfo.schemas.responses.products import ProductSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import HotfixSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import NetIPAddressSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import NetAdapterSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import PrinterSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import PSInstalledVersionsSchema
from reveal.webapi.sysinfo.schemas.arguments.hosts import HostByNameSearchSchema
from reveal.webapi.sysinfo.schemas.arguments.hosts import HostByIPSearchSchema


@bp.route("/hosts/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=HostSchema(many=True))
@bp.doc(description="Returns a list of all hosts.",
        summary="Find all hosts",
        security='ApiKeyAuth' )
def get_host_list():
    return Host.query.all()


@bp.get("/hosts/<int:host_id>")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=HostSchema)
@bp.doc(description="Returns the host with the specified id.",
        summary="Find a host by ID",
        security='ApiKeyAuth')
def get_host_by_id(host_id):
    return Host.query.get_or_404(host_id)


@bp.post("/hosts/by-name/")
@bp.auth_required(auth)
@bp.input(schema=HostByNameSearchSchema, location='json')
@bp.output(status_code=HTTPStatus.OK, schema=HostSchema(many=True))
@bp.doc(description="Returns a list of hosts containing the specified hostname.",
        summary="Find a host by hostname",
        security='ApiKeyAuth')
def get_host_by_name(search_data):
    return Host.query.filter(Host.Hostname.like("%"+search_data['name']+ "%" )).all()


@bp.post("/hosts/by-ip/")
@bp.auth_required(auth)
@bp.input(schema=HostByIPSearchSchema)
@bp.output(status_code=HTTPStatus.OK,
           schema=HostSchema(many=True))
@bp.doc(description="Returns a list of hosts containing the specified hostname.",
        summary="Find a host by hostname",
        security='ApiKeyAuth')
def get_host_by_ip(search_data):
    ips = NetIPAddress.query.filter(NetIPAddress.IP.ilike("%"+search_data['ip']+"%")).all()
    hosts = [i.Host for i in ips]
    return hosts


@bp.get("/hosts/<int:host_id>/users/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=UserSchema(many=True))
@bp.doc(description="Returns a list of all users from a specific host.",
        summary="Find all users of a specific host",
        security='ApiKeyAuth')
def get_users_by_host(host_id):
    return User.query.filter(User.Host_id == host_id).all()


@bp.get("/hosts/<int:host_id>/groups/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=GroupSchema(many=True))
@bp.doc(description="Returns a list of all groups from a specific host.",
        summary="Find all groups of a specific host",
        security='ApiKeyAuth')
def get_groups_by_host(host_id):
    return Group.query.filter(Group.Host_id == host_id).all()


@bp.get("/hosts/<int:host_id>/products/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ProductSchema(many=True))
@bp.doc(description="Return a list of installed products from a specific host.",
        summary="Find all products of a specific host",
        security='ApiKeyAuth')
def get_products_by_host(host_id):
    return Product.query.filter(Product.Host_id == host_id).all()


@bp.get("/hosts/<int:host_id>/hotfixes/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=HotfixSchema(many=True))
@bp.doc(description="Return a list of installed hotfixes from a specific host.",
        summary="Find all hotfixes installed on a specific host",
        security='ApiKeyAuth')
def get_hotfixes_by_host(host_id):
    return Hotfix.query.filter(Hotfix.Host_id == host_id).all()


@bp.get("/hosts/<int:host_id>/netadapters/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=NetAdapterSchema(many=True))
@bp.doc(description="Return a list of network adapters from a specific host.",
        summary="Find all network adapters on a specific host",
        security='ApiKeyAuth')
def get_netadapter_by_host(host_id):
    return NetAdapter.query.filter(NetAdapter.Host_id == host_id).all()


@bp.get("/hosts/<int:host_id>/netipaddresses/")
@bp.auth_required(auth)
@bp.doc(description="Return a list of IP addresses from a specific host.",
        summary="Find all IP addresses on a specific host",
        security='ApiKeyAuth')
@bp.output(status_code=HTTPStatus.OK, schema=NetIPAddressSchema(many=True))
def get_ips_by_host(host_id):
    return NetIPAddress.query.filter(NetIPAddress.Host_id == host_id).all()



@bp.get("/hosts/<int:host_id>/psversions/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=PSInstalledVersionsSchema(many=True))
@bp.doc(description="Return a list of PowerShell versions from a specific host.",
        summary="Find all PowerShell versions on a specific host",
        security='ApiKeyAuth')
def get_psversion_by_host(host_id):
    return PSInstalledVersions.query.filter(PSInstalledVersions.Host_id == host_id).all()


@bp.get("/hosts/<int:host_id>/printers/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=PrinterSchema(many=True))
@bp.doc(description="Return a list of installed printers from a specific host.",
    summary="Find all installed printers on a specific host",
    security='ApiKeyAuth')
def get_printers_by_host(host_id):
    return Printer.query.filter(Printer.Host_id == host_id).all()
