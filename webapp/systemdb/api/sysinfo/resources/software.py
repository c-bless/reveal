from http import HTTPStatus
from flask.views import MethodView
from flask_smorest import Blueprint
from sqlalchemy import and_
from flask_login import login_required

from webapp.systemdb.models.sysinfo import Product
from webapp.systemdb.api.sysinfo.schemas.responses.product import ProductSchema
from webapp.systemdb.api.sysinfo.schemas.arguments.products import ProductNameSearchSchema
from webapp.systemdb.api.sysinfo.schemas.arguments.services import ServicePermissionSearchSchema

from webapp.systemdb.models.sysinfo import Service, ServiceACL
from webapp.systemdb.api.sysinfo.schemas.responses.service import ServiceSchema, ServiceACLSchema

from webapp.systemdb.models.eol import EoL
from webapp.systemdb.api.sysinfo.schemas.responses.eol import EoLSchema

blp = Blueprint('SysinfoCollector - Software', 'sysinfo_sw_api' , url_prefix='/api/sysinfo',
        description="Review products, services and hotfixes collected by sysinfo-collector PowerShell scripts.")

###################################################################################
# Product details
###################################################################################
@blp.route("/products/<int:product_id>")
@login_required
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
    @blp.arguments(ProductNameSearchSchema, location="json")
    @blp.response(HTTPStatus.OK.value, ProductSchema(many=True))
    def post(self, search_data):
        products = Product.query.filter(Product.Name.like("%"+search_data['name']+"%")).all()
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


@blp.route("/services/acls/")
class ServiceACLListAllView(MethodView):

    @blp.doc(description="Returns a list of all ACLs for services from all hosts.",
             summary="Find all services ACLs"
             )
    @blp.response(HTTPStatus.OK.value, ServiceACLSchema(many=True))
    def get(self):
        return ServiceACL.query.all()


@blp.route("/services/acls/by-permission/")
class ServiceACLByPermissionListView(MethodView):
    @blp.doc(description="Returns a list of all ACLs for services based on specified search filter",
             summary="Find product by permission"
             )
    @blp.arguments(ServicePermissionSearchSchema, location="json")
    @blp.response(HTTPStatus.OK.value, ServiceACLSchema(many=True))
    def post(self, search_data):

        services = ServiceACL.query.filter(and_(ServiceACL.AccountName.like("%" + search_data['Accountname'] + "%"),
                                                ServiceACL.AccessRight.like("%" + search_data['Permission'] + "%")
                                                )).all()
        return services


@blp.route("/eol-dates/")
class EoLDateListView(MethodView):

    @blp.doc(description="Return a list end-of-life dates",
             summary="Find all end-of-life dates"
             )
    @blp.response(HTTPStatus.OK.value, EoLSchema(many=True))
    def get(self):
        return EoL.query.all()
