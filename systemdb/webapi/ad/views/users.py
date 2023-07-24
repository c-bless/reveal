from http import HTTPStatus
from apiflask import HTTPError

from systemdb.core.models.activedirectory import ADUser

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.ad.schemas.responses.domain import ADUserSchema


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

