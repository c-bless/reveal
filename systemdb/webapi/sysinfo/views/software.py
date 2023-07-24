from http import HTTPStatus
from sqlalchemy import and_

from systemdb.webapi.sysinfo.views import bp
from systemdb.webapi.extentions import auth

from systemdb.core.models.sysinfo import Service
from systemdb.core.models.sysinfo import ServiceACL
from systemdb.webapi.sysinfo.schemas.arguments.services import ServicePermissionSearchSchema
from systemdb.webapi.sysinfo.schemas.responses.services import ServiceSchema
from systemdb.webapi.sysinfo.schemas.responses.services import ServiceACLSchema

from systemdb.core.models.sysinfo import Product
from systemdb.webapi.sysinfo.schemas.arguments.products import ProductNameSearchSchema
from systemdb.webapi.sysinfo.schemas.responses.products import ProductSchema


###################################################################################
# Product details
###################################################################################
@bp.get("/products/<int:product_id>")
@bp.auth_required(auth)
@bp.doc(description="Return an installed product based on specified ID",
        summary="Find product by ID",
        security='ApiKeyAuth')
@bp.output(status_code=HTTPStatus.OK, schema=ProductSchema)
def get_product_by_id(product_id):
    return Product.query.get_or_404(product_id)


@bp.post("/products/search/")
@bp.auth_required(auth)
@bp.input(schema=ProductNameSearchSchema, location="json")
@bp.output(status_code=HTTPStatus.OK, schema=ProductSchema(many=True))
@bp.doc(description="Return an installed product based on specified search filter",
        summary="Find product by name",
        security='ApiKeyAuth')
def get_products_by_name(search_data):
    products = Product.query.filter(Product.Name.like("%"+search_data['name']+"%")).all()
    return products


@bp.get("/products/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ProductSchema(many=True))
@bp.doc(description="Return a list of installed products from all hosts.",
         summary="Find all products",
        security='ApiKeyAuth')
def get_product_list():
    return Product.query.all()


@bp.get("/products/by-host/<int:host_id>")
@bp.auth_required(auth)
@bp.doc(description="Return a list of installed products from a specific host.",
        summary="Find all products of a specific host",
        security='ApiKeyAuth')
@bp.response(HTTPStatus.OK.value, ProductSchema(many=True))
def get_products_by_host(host_id):
    return Product.query.filter(Product.Host_id == int(host_id)).all()


@bp.get("/services/<int:service_id>")
@bp.auth_required(auth)
@bp.doc(description="Return a service based on specified ID",
        summary="Find service by ID",
        security='ApiKeyAuth')
@bp.response(HTTPStatus.OK.value, ServiceSchema)
def get_service_by_id(id):
    return Service.query.get_or_404(id)


@bp.get("/services/")
@bp.auth_required(auth)
@bp.doc(description="Returns a list of all installed services from all hosts.",
        summary="Find all services",
        security='ApiKeyAuth')
@bp.output(HTTPStatus.OK.value, ServiceSchema(many=True))
def get_service_list():
    return Service.query.all()


@bp.get("/services/acls/")
@bp.auth_required(auth)
@bp.doc(description="Returns a list of all ACLs for services from all hosts.",
        summary="Find all services ACLs",
        security='ApiKeyAuth')
@bp.output(status_code=HTTPStatus.OK, schema=ServiceACLSchema(many=True))
def get_service_acl_list():
    return ServiceACL.query.all()


@bp.post("/services/acls/by-permission/")
@bp.auth_required(auth)
@bp.doc(description="Returns a list of all ACLs for services based on specified search filter",
         summary="Find product by permission",
    security='ApiKeyAuth')
@bp.input(schema=ServicePermissionSearchSchema, location="json")
@bp.output(status_code=HTTPStatus.OK, schema=ServiceACLSchema(many=True))
def get_service_acls_by_permission(search_data):
    services = ServiceACL.query.filter(and_(ServiceACL.AccountName.like("%" + search_data['Accountname'] + "%"),
                                            ServiceACL.AccessRight.like("%" + search_data['Permission'] + "%")
                                            )).all()
    return services

