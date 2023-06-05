from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint


from ....models.sysinfo import Host, Service, Product, User, Group, NetIPAddress
from ..schemas.responses.hosts import HostSchema, UserSchema, GroupSchema
from ..schemas.responses.service import ServiceSchema
from ..schemas.responses.product import ProductSchema

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
class HostByIdView(MethodView):

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
