from http import HTTPStatus
from sqlalchemy import and_
from apiflask import HTTPError

from systemdb.webapi.ad.domain import bp
from systemdb.webapi.extentions import auth

from systemdb.core.models.activedirectory import ADDomain
from systemdb.core.models.activedirectory import ADGroup
from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.webapi.ad.schemas.arguments.domain import ADDomainByNameSchema
from systemdb.webapi.ad.schemas.responses.domain import ADDomainSchema
from systemdb.webapi.ad.schemas.responses.domain import ADGroupWithMembersSchema


@bp.get("/domain")
@bp.auth_required(auth)
@bp.output(schema=ADDomainSchema(many=True), status_code=HTTPStatus.OK, description="List of all imported domains.")
@bp.doc(description="Returns a list of all domains. In case no domain is found an empty list is returned.",
        summary="Find a list of imported domains.")
@bp.doc(security='ApiKeyAuth')
def get_domains():
    return ADDomain.query.all()


@bp.get("/domain/<int:id>")
@bp.auth_required(auth)
@bp.output(schema=ADDomainSchema, status_code=HTTPStatus.OK, description="An imported domain")
@bp.doc(description="Returns the domain with the specified id.",
        summary="Find a domain by ID"
)
def get_domain_by_id(id):
        return ADDomain.query.get_or_404(id)


@bp.post("/domain/by-name/")
@bp.auth_required(auth)
@bp.input(ADDomainByNameSchema, location='json')
@bp.output(status_code=HTTPStatus.OK, schema=ADDomainSchema(many=True),
           description="An domain matching specified creteria.")
@bp.doc(description="Returns a list of domains containing the specified name.",
        summary="Find domains by name"
        )
@bp.doc(security='ApiKeyAuth')
def get_domain_by_name(search_data):
        return ADDomain.query.filter(ADDomain.Name.ilike("%"+search_data['name']+"%")).all()


@bp.get("/domain/<int:domain_id>/groups/domainadmins/")
@bp.auth_required(auth)
@bp.doc(description="Returns the domain admin group for the specified domain.",
        summary="Find the domain admin group for the specified domain."
)
@bp.output(HTTPStatus.OK, ADGroupWithMembersSchema, description="Domain Admin group")
def get_domain_admins_for_domain(domain_id: int):
    try:
        return ADGroup.query.filter(
            and_(ADGroup.Domain_id == domain_id, ADGroup.SID == SID_LOCAL_ADMIN_GROUP)).first()
    except:
        return HTTPError(404, "Domain/Group not found.")
