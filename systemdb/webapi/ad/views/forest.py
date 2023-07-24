from http import HTTPStatus
from apiflask import HTTPError

from systemdb.core.models.activedirectory import ADForest
from systemdb.core.models.activedirectory import ADForestSite
from systemdb.core.models.activedirectory import ADForestGlobalCatalog

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.ad.schemas.arguments.forest import ADForestByNameSchema

from systemdb.webapi.ad.schemas.responses.domain import ADForestSchema
from systemdb.webapi.ad.schemas.responses.domain import ADForestSiteSchema
from systemdb.webapi.ad.schemas.responses.domain import ADForestGlobalCatalogSchema


@bp.get("/forest/")
@bp.auth_required(auth)
@bp.doc(description="Returns a list of all forests. In case no forest is found an empty list is returned.",
        summary="Find all forest.",
        security='ApiKeyAuth'
        )
@bp.output(status_code=HTTPStatus.OK, schema=ADForestSchema(many=True), description="List of forests")
def get_ad_forest_list():
    return ADForest.query.all()


@bp.get("/forest/<int:id>")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ADForestSchema, description= "Forest with specified ID")
@bp.doc(description="Returns the forest with the specified id.",
        summary="Find a forest by ID",
        security='ApiKeyAuth'
        )
def get_ad_forest_by_id(id):
    return ADForest.query.get_or_404(id)


@bp.post("/forest/by-name/")
@bp.auth_required(auth)
@bp.input(schema=ADForestByNameSchema, location='json')
@bp.output(status_code=HTTPStatus.OK, schema=ADForestSchema(many=True), description="List of forests")
@bp.doc(description="Returns a list of forests containing the specified name.",
        summary="Find forest by name",
        security='ApiKeyAuth')
def get_ad_forest_by_name(search_data):
    return ADForest.query.filter(ADForest.Name.like("%"+search_data['name']+"%")).all()


@bp.get("/forest/<int:forest_id>/globalcatalogs/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ADForestGlobalCatalogSchema(many=True),
              description="List of global catalogs.")
@bp.doc(description="Returns a list of all global catalogs in the forest with the specified ID.",
        summary="Find a list of all global catalogs in the forest with the specified ID.",
        security='ApiKeyAuth')
def get_ad_gc_list(forest_id):
    try:
        return ADForestGlobalCatalog.query.filter(ADForestGlobalCatalog.Forest_id == forest_id).all()
    except:
        return HTTPError(404, "Forest not found.")


@bp.get("/forest/<int:forest_id>/sites/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ADForestSiteSchema(many=True),
              description="List of sites.")
@bp.doc(description="Returns a list of sites for the forest with the specified ID.",
        summary="Find a list of sites for the forest with the specified ID.",
        security='ApiKeyAuth')
def get_ad_site_list(forest_id):
    try:
        return ADForestSite.query.filter(ADForestSite.Forest_id == forest_id).all()
    except:
        return HTTPError(404, "Forest not found.")

