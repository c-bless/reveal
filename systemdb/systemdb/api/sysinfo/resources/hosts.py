from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint


from ....models.sysinfo import Host, Service, Product
from ..schemas.responses.hosts import HostSchema
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
        return Service.query.filter(Service.Host_id == id).all()


@blp.route("/hosts/<int:host_id>/products/")
class HostListProductsView(MethodView):

    @blp.doc(description="Return a list of installed products from a specific host.",
             summary="Find all products of a specific host"
             )
    @blp.response(HTTPStatus.OK.value, ProductSchema(many=True))
    def get(self):
        return Product.query.filter(Product.Host_id == id).all()
