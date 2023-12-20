from http import HTTPStatus
from apiflask import HTTPError

from reveal.core.models.activedirectory import ADUser

from reveal.webapi.ad import bp
from reveal.webapi.extentions import auth

from reveal.webapi.ad.schemas.responses.domain import ADUserSchema, ADDomain
from reveal.webapi.ad.schemas.arguments.users import UserByDomainSearchSchema


@bp.get("/domain/<int:domain_id>/users/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADUserSchema(many=True),
           description="List of users in the domain. If no users are assigned to the domain an empty list is returned.")
@bp.doc(description="Returns a list of all domain users for the domain with the specified ID.",
        summary="Find a list of all domain users for the domain with the specified ID.",
        security='ApiKeyAuth')
def get_domain_user_list(domain_id):
    try:
        return ADUser.query.filter(ADUser.Domain_id == domain_id).all()
    except:
        return HTTPError(404, "Domain not found.")


@bp.get("/users/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADUserSchema(many=True),
           description="List of users across all domains. If no users were found an empty list is returned.")
@bp.doc(description="Returns a list of all domain users across all domains.",
        summary="Find a list of all domain users across all domains.",
        security='ApiKeyAuth')
def get_domain_user_list_all():
    return ADUser.query.all()


@bp.post("/users/by-domain/")
@bp.auth_required(auth)
@bp.input(schema=UserByDomainSearchSchema, location="json")
@bp.output(status_code=HTTPStatus.OK,
           schema=ADUserSchema(many=True),
           description="List of users in the domain. If no users are assigned to the domain an empty list is returned.")
@bp.doc(description="Returns a list of all domain users for the domain specified in parameters.",
        summary="Find all domain users for the domain specified in parameters",
        security='ApiKeyAuth'
        )
def post_domain_user_by_domain(search_data):
    user_filter_list = []
    domain_filter_list = []
    if "id" in search_data:
        user_filter_list.append(ADUser.Domain_id == search_data["id"])
    if "Domainname" in search_data:
        domain_filter_list.append(ADDomain.Name.ilike( "%"+search_data["Domainname"]+"%"))
    if "NETBIOS" in search_data:
        domain_filter_list.append(ADDomain.NetBIOSName.ilike( "%"+search_data["NETBIOS"]+"%"))

    return ADUser.query.filter(*user_filter_list).join(ADDomain).filter().all()

