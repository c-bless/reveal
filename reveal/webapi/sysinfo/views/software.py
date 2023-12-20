from http import HTTPStatus
from sqlalchemy import and_

from reveal.webapi.sysinfo.views import bp
from reveal.webapi.extentions import auth

from reveal.core.models.sysinfo import Product
from reveal.webapi.sysinfo.schemas.arguments.products import ProductNameSearchSchema
from reveal.webapi.sysinfo.schemas.responses.products import ProductSchema


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
@bp.output(status_code=HTTPStatus.OK, schema=ProductSchema(many=True))
def get_products_filtered_by_host(host_id):
    return Product.query.filter(Product.Host_id == int(host_id)).all()

