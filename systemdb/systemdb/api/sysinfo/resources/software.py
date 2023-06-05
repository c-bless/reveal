from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint

from ....models.sysinfo import Product
from ..schemas.responses.product import ProductSchema
from ..schemas.arguments.products import ProductSearchNameSchema

from ....models.sysinfo import Service
from ..schemas.responses.service import ServiceSchema

blp = Blueprint('SysinfoCollector - Software', 'sysinfo_sw_api' , url_prefix='/api/sysinfo',
        description="Review products, services and hotfixes collected by sysinfo-collector PowerShell scripts.")

###################################################################################
# Product details
###################################################################################
@blp.route("/products/<int:product_id>")
class ProductByIdView(MethodView):

    @blp.doc(description="Return an installed product based on specified ID",
             summary="Find product by ID"
             )
    @blp.response(HTTPStatus.OK.value, ProductSchema)
    def get(self, product_id):
        return Product.query.get_or_404(product_id)

@blp.route("/products/search/")
class ProductSearchView(MethodView):

    @blp.doc(description="Return an installed product based on specified search filter",
             summary="Find product by name"
             )
    @blp.arguments(ProductSearchNameSchema, location="json")
    @blp.response(HTTPStatus.OK.value, ProductSchema(many=True))
    def post(self, search_data):
        products = Product.query.filter(Product.Name.like("%"+search_data['name']+ "%" )).all()
        return products

@blp.route("/products/")
class ProductListView(MethodView):

    @blp.doc(description="Return a list of installed products from all hosts.",
             summary="Find all products"
             )
    @blp.response(HTTPStatus.OK.value, ProductSchema(many=True))
    def get(self):
        return Product.query.all()


@blp.route("/products/by-host/<int:host_id>")
class ProductListByHostView(MethodView):

    @blp.doc(description="Return a list of installed products from a specific host.",
             summary="Find all products of a specific host"
             )
    @blp.response(HTTPStatus.OK.value, ProductSchema(many=True))
    def get(self):
        return Product.query.filter(Product.Host_id == id).all()


@blp.route("/services/<int:service_id>")
class ServiceView(MethodView):

    @blp.doc(description="Return a service based on specified ID",
             summary="Find service by ID"
             )
    @blp.response(HTTPStatus.OK.value, ServiceSchema)
    def get(self, id):
        return Service.query.get_or_404(id)


@blp.route("/services/")
class ServiceListAllView(MethodView):

    @blp.doc(description="Returns a list of all installed services from all hosts.",
             summary="Find all services"
             )
    @blp.response(HTTPStatus.OK.value, ServiceSchema(many=True))
    def get(self):
        return Service.query.all()

