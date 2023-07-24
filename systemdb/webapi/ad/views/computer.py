from http import HTTPStatus
from apiflask import HTTPError

from systemdb.core.models.activedirectory import ADComputer
from systemdb.core.models.activedirectory import ADDomainController

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.ad.schemas.responses.domain import ADComputerSchema
from systemdb.webapi.ad.schemas.responses.domain import ADDomainControllerSchema


@bp.get("/domain/<int:domain_id>/computers/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ADComputerSchema(many=True), description="List of computers in the domain. "
                                    "If no computers are assigned to the domain an empty list is returned")
@bp.doc(description="Returns a list of all domain computers for the domain with the specified ID.",
        summary="Find a list of all domain computers for the domain with the specified ID.",
        security='ApiKeyAuth'
             )
def get_ad_computer_list(domain_id):
    try:
        return ADComputer.query.filter(ADComputer.Domain_id == domain_id).all()
    except:
        return HTTPError(404, "Domain not found.")


@bp.get("/domain/<int:domain_id>/DCs/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ADDomainControllerSchema(many=True), description="List of DCs in the domain. "
                                "If no views controllers are assigned to the domain an empty list is returned")
@bp.doc(description="Returns a list of all domain controllers for the domain with the specified ID.",
        summary="Find a list of all domain controllers for the domain with the specified ID.",
        security='ApiKeyAuth'
         )
def get_ad_dc_list(domain_id):
    try:
        return ADDomainController.query.filter(ADDomainController.Domain_id == domain_id).all()
    except:
        return HTTPError(404, "Domain not found.")
