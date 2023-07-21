from http import HTTPStatus

from systemdb.webapi.ad.domain import bp
from systemdb.webapi.ad.schemas.arguments.domain import ADDomainByNameSchema
from systemdb.webapi.ad.schemas.responses.domain import ADDomainSchema
from systemdb.core.models.activedirectory import ADDomain


@bp.get("/domain")
@bp.output(schema=ADDomainSchema(many=True), description="List of all imported domains.")
@bp.doc(description="Returns a list of all domains. In case no domain is found an empty list is returned.",
        summary="Find a list of imported domains.")
def get_domains():
    return ADDomain.query.all()


@bp.get("/domain/<int:id>")
@bp.output(schema=ADDomainSchema, status_code=HTTPStatus.OK, description="An imported domain")
@bp.doc(description="Returns the domain with the specified id.",
        summary="Find a domain by ID"
)
def get_domain_by_id(id):
        return ADDomain.query.get_or_404(id)


@bp.post("/domain/by-name/")
@bp.input(ADDomainByNameSchema, location='json')
@bp.output(status_code=HTTPStatus.OK.value, schema=ADDomainSchema(many=True),
           description="An domain matching specified creteria.")
@bp.doc(description="Returns a list of domains containing the specified name.",
        summary="Find domains by name"
        )
def get_domain_by_name(search_data):
        return ADDomain.query.filter(ADDomain.Name.ilike("%"+search_data['name']+"%")).all()


