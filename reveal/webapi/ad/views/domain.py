from http import HTTPStatus
from apiflask import HTTPError

from reveal.core.models.activedirectory import ADDomain
from reveal.core.models.activedirectory import ADPasswordPolicy

from reveal.webapi.ad import bp
from reveal.webapi.extentions import auth

from reveal.webapi.ad.schemas.arguments.domain import ADDomainByNameSchema
from reveal.webapi.ad.schemas.responses.domain import ADDomainSchema
from reveal.webapi.ad.schemas.responses.domain import ADPasswordPolicySchema


@bp.get("/domain")
@bp.auth_required(auth)
@bp.output(schema=ADDomainSchema(many=True),
           status_code=HTTPStatus.OK,
           description="List of all imported domains.")
@bp.doc(description="Returns a list of all domains. In case no views is found an empty list is returned.",
        summary="Find a list of imported domains.",
        security='ApiKeyAuth')
def get_domains():
    return ADDomain.query.all()


@bp.get("/domain/<int:id>")
@bp.auth_required(auth)
@bp.output(schema=ADDomainSchema,
           status_code=HTTPStatus.OK,
           description="An imported views")
@bp.doc(description="Returns the domain with the specified id.",
        summary="Find a domain by ID",
        security='ApiKeyAuth')
def get_domain_by_id(id):
        return ADDomain.query.get_or_404(id)


@bp.post("/domain/by-name/")
@bp.auth_required(auth)
@bp.input(schema=ADDomainByNameSchema, location='json')
@bp.output(status_code=HTTPStatus.OK,
           schema=ADDomainSchema(many=True),
           description="An views matching specified criteria.")
@bp.doc(description="Returns a list of domains containing the specified name.",
        summary="Find domains by name",
        security='ApiKeyAuth'
)
def get_domain_by_name(search_data):
        return ADDomain.query.filter(ADDomain.Name.ilike("%"+search_data['name']+"%")).all()


@bp.get("/domain/<int:domain_id>/pw-policies/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADPasswordPolicySchema(many=True),
           description="List of password policies in the domain. ")
@bp.doc(description="Returns a list of all password policies (default and fine grained) for the domain with the "
                    "specified ID.",
        summary="Find a list of all password policies for the domain with the specified ID.",
        security='ApiKeyAuth')
def get_domain_pw_policy_list(domain_id):
    try:
        return ADPasswordPolicy.query.filter(ADPasswordPolicy.Domain_id == domain_id).all()
    except:
        return HTTPError(404, "Domain not found.")
