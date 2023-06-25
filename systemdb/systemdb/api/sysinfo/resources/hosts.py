from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint


from ....models.sysinfo import Host, Service, Product, User, Group, NetIPAddress, Hotfix, NetAdapter, Printer, \
    ConfigCheck, PSInstalledVersions
from ..schemas.responses.hosts import HostSchema, UserSchema, GroupSchema, HotfixSchema, NetAdapterSchema, \
    PrinterSchema, PSInstalledVersionsSchema, ConfigCheckSchema, NetIPAddressSchema
from ..schemas.responses.service import ServiceSchema
from ..schemas.responses.product import ProductSchema
from ..schemas.responses.usermgmt import UserGroupAssignment
from ....sysinfo.reports.usermgmt import get_direct_domainuser_assignments

blp = Blueprint('SysinfoCollector - Hosts', 'sysinfo_hosts_api' , url_prefix='/api/sysinfo',
                           description="Review hosts collected by sysinfo-collector PowerShell scripts.")


@blp.route("/hosts/<int:id>")
class HostByIdView(MethodView):

    @blp.doc(description="Returns the host with the specified id.",
             summary="Find a host by ID"
             )
    @blp.response(HTTPStatus.OK.value, HostSchema)
    def get(self, id):
        return Host.query.get_or_404(id)

@blp.route("/hosts/by-name/<string:name>")
class HostByNameView(MethodView):

    @blp.doc(description="Returns a list of hosts containing the specified hostname.",
             summary="Find a host by hostname"
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self, name):
        return Host.query.filter(Host.Hostname.like("%"+name+ "%" )).all()


@blp.route("/hosts/by-ip/<string:ip>")
class HostByIPView(MethodView):

    @blp.doc(description="Returns a list of hosts containing the specified hostname.",
             summary="Find a host by hostname"
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self, ip):
        ips = NetIPAddress.query.filter(NetIPAddress.IP.like("%"+ip+"%")).all()
        ip_ids = []
        for ip in ips:
            ip_ids.append(ip.id)
        hosts = Host.query.filter(Host.id.in_(ip_ids)).all()
        return hosts


@blp.route("/hosts/")
class HostListAllView(MethodView):

    @blp.doc(description="Returns a list of all hosts.",
             summary="Find all hosts"
             )
    @blp.response(HTTPStatus.OK.value, HostSchema(many=True))
    def get(self):
        return Host.query.all()


@blp.route("/hosts/<int:host_id>/services/")
class HostListServicesView(MethodView):

    @blp.doc(description="Returns a list of all installed services from a specific host.",
             summary="Find all services of a specific host"
             )
    @blp.response(HTTPStatus.OK.value, ServiceSchema(many=True))
    def get(self, host_id):
        return Service.query.filter(Service.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/users/")
class HostListUsersView(MethodView):

    @blp.doc(description="Returns a list of all users from a specific host.",
             summary="Find all users of a specific host"
             )
    @blp.response(HTTPStatus.OK.value, UserSchema(many=True))
    def get(self, host_id):
        return User.query.filter(User.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/groups/")
class HostListGroupsView(MethodView):

    @blp.doc(description="Returns a list of all groups from a specific host.",
             summary="Find all groups of a specific host"
             )
    @blp.response(HTTPStatus.OK.value, GroupSchema(many=True))
    def get(self, host_id):
        return Group.query.filter(Group.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/products/")
class HostListProductsView(MethodView):

    @blp.doc(description="Return a list of installed products from a specific host.",
             summary="Find all products of a specific host"
             )
    @blp.response(HTTPStatus.OK.value, ProductSchema(many=True))
    def get(self, host_id):
        return Product.query.filter(Product.Host_id == id).all()


@blp.route("/hosts/<int:host_id>/hotfixes/")
class HostListHotfixesView(MethodView):

    @blp.doc(description="Return a list of installed hotfixes from a specific host.",
             summary="Find all hotfixes installed on a specific host"
             )
    @blp.response(HTTPStatus.OK.value, HotfixSchema(many=True))
    def get(self, host_id):
        return Hotfix.query.filter(Hotfix.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/netadapters/")
class HostListNetAdaptersView(MethodView):

    @blp.doc(description="Return a list of network adapters from a specific host.",
             summary="Find all network adapters on a specific host"
             )
    @blp.response(HTTPStatus.OK.value, NetAdapterSchema(many=True))
    def get(self, host_id):
        return NetAdapter.query.filter(NetAdapter.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/netipaddresses/")
class HostListNetIPAddressesView(MethodView):

    @blp.doc(description="Return a list of IP addresses from a specific host.",
             summary="Find all IP addresses on a specific host"
             )
    @blp.response(HTTPStatus.OK.value, NetIPAddressSchema(many=True))
    def get(self, host_id):
        return NetIPAddress.query.filter(NetIPAddress.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/configchecks/")
class HostListConfigChecksView(MethodView):

    @blp.doc(description="Return a list of performed config checks of a specific host.",
             summary="Find all performed config checks on a specific host"
             )
    @blp.response(HTTPStatus.OK.value, ConfigCheckSchema(many=True))
    def get(self, host_id):
        return ConfigCheck.query.filter(ConfigCheck.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/psversions/")
class HostListPSVersionsView(MethodView):

    @blp.doc(description="Return a list of PowerShell versions from a specific host.",
             summary="Find all PowerShell versions on a specific host"
             )
    @blp.response(HTTPStatus.OK.value, PSInstalledVersionsSchema(many=True))
    def get(self, host_id):
        return PSInstalledVersions.query.filter(PSInstalledVersions.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/printers/")
class HostListPrintersView(MethodView):

    @blp.doc(description="Return a list of installed printers from a specific host.",
             summary="Find all installed printers on a specific host"
             )
    @blp.response(HTTPStatus.OK.value, PrinterSchema(many=True))
    def get(self, host_id):
        return Printer.query.filter(Printer.Host_id == host_id).all()


@blp.route("/hosts/<int:host_id>/printers/")
class HostListPrintersView(MethodView):

    @blp.doc(description="Return a list of installed printers from a specific host.",
             summary="Find all installed printers on a specific host"
             )
    @blp.response(HTTPStatus.OK.value, PrinterSchema(many=True))
    def get(self, host_id):
        return Printer.query.filter(Printer.Host_id == host_id).all()


@blp.route("/usermgmt/assignments/domainusers/")
class HostListPrintersView(MethodView):

    @blp.doc(description="Return a list of domain users that area directly assigned to a local group.",
             summary="Find domain users that area directly assigned to a local group"
             )
    @blp.response(HTTPStatus.OK.value, UserGroupAssignment(many=True))
    def get(self, host_id):
        members = get_direct_domainuser_assignments()
        return members