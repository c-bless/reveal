from http import HTTPStatus

from flask import current_app
from sqlalchemy import func

from reveal.core.extentions import db

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
from reveal.webapi.sysinfo.schemas.arguments.hosts import HostAssignmentSchema
from reveal.webapi.sysinfo.schemas.arguments.hosts import HostBulkAssignmentSchema
from reveal.webapi.sysinfo.schemas.arguments.hosts import HOST_ASSIGNMENT_FIELDS
from reveal.webapi.sysinfo.schemas.responses.hosts import HostBulkAssignmentResultSchema


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
@bp.input(schema=HostByNameSearchSchema, location='json', arg_name="search_data")
@bp.output(status_code=HTTPStatus.OK, schema=HostSchema(many=True))
@bp.doc(description="Returns a list of hosts containing the specified hostname.",
        summary="Find a host by hostname",
        security='ApiKeyAuth')
def get_host_by_name(search_data):
    return Host.query.filter(Host.Hostname.like("%"+search_data['name']+ "%" )).all()


@bp.post("/hosts/by-ip/")
@bp.auth_required(auth)
@bp.input(schema=HostByIPSearchSchema, arg_name="search_data")
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


#####################################################################################
# Update of the host assignment (system group, location, label)
#####################################################################################
def apply_host_assignment(host: Host, data: dict) -> dict:
    """
    Sets the assignment fields contained in data on the host. Empty strings and null remove the value.
    Changes are written to the application log (who, which host, old -> new value).

    :return: dictionary of the changed fields: {field: (old value, new value)}
    """
    changes = {}
    for field in HOST_ASSIGNMENT_FIELDS:
        if field in data:
            new_value = data[field] or None
            old_value = getattr(host, field)
            if old_value != new_value:
                setattr(host, field, new_value)
                changes[field] = (old_value, new_value)
    if changes:
        user = auth.current_user
        current_app.logger.info("Host assignment changed by %s: host id=%s hostname=%s %s",
                                getattr(user, "Username", "?"), host.id, host.Hostname, changes)
    return changes


@bp.patch("/hosts/<int:host_id>")
@bp.auth_required(auth)
@bp.input(schema=HostAssignmentSchema, location='json', arg_name="data")
@bp.output(status_code=HTTPStatus.OK, schema=HostSchema)
@bp.doc(description="Updates the system group, location and/or label of the host with the specified id. Only the "
                    "fields contained in the request are changed, null or an empty string removes the value.",
        summary="Update system group, location and label of a host",
        security='ApiKeyAuth')
def update_host_assignment(host_id, data):
    host = Host.query.get_or_404(host_id)
    apply_host_assignment(host, data)
    db.session.commit()
    return host


@bp.patch("/hosts/assignment")
@bp.auth_required(auth)
@bp.input(schema=HostBulkAssignmentSchema, location='json', arg_name="data")
@bp.output(status_code=HTTPStatus.OK, schema=HostBulkAssignmentResultSchema)
@bp.doc(description="Updates the system group, location and/or label of several hosts. The hosts are selected "
                    "either by their IDs (host_ids) or by their hostnames (hostnames, all hosts with this hostname). "
                    "All hosts are updated in one transaction. Requested IDs / hostnames without matching host are "
                    "returned in not_found.",
        summary="Update system group, location and label of several hosts",
        security='ApiKeyAuth')
def update_hosts_assignment(data):
    if "host_ids" in data:
        requested = list(dict.fromkeys(data["host_ids"]))
        hosts = Host.query.filter(Host.id.in_(requested)).order_by(Host.id).all()
        found = {h.id for h in hosts}
    else:
        # hostnames are compared case-insensitive (Windows hostnames are not case-sensitive)
        requested = list(dict.fromkeys(data["hostnames"]))
        hosts = (Host.query.filter(func.lower(Host.Hostname).in_([n.lower() for n in requested]))
                 .order_by(Host.id).all())
        found = {(h.Hostname or "").lower() for h in hosts}
        requested_keys = [n.lower() for n in requested]
    updated = sum(1 for h in hosts if apply_host_assignment(h, data))
    db.session.commit()
    if "host_ids" in data:
        not_found = [r for r in requested if r not in found]
    else:
        not_found = [r for r, k in zip(requested, requested_keys) if k not in found]
    return {"updated": updated, "hosts": hosts, "not_found": not_found}
