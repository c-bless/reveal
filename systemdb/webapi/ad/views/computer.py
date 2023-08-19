from http import HTTPStatus
from apiflask import HTTPError
from sqlalchemy import and_

from systemdb.core.models.activedirectory import ADComputer
from systemdb.core.models.activedirectory import ADDomainController
from systemdb.core.models.activedirectory import ADSPN
from systemdb.core.models.activedirectory import ADDomain

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.ad.schemas.responses.domain import ADComputerSchema
from systemdb.webapi.ad.schemas.arguments.computer import ADComputerBySPNSchema
from systemdb.webapi.ad.schemas.responses.domain import ADDomainControllerSchema


@bp.get("/domain/<int:domain_id>/computer/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADComputerSchema(many=True),
           description="List of computers in the domain. If no computers are assigned to the domain "
                       "an empty list is returned")
@bp.doc(description="Returns a list of all domain computers for the domain with the specified ID.",
        summary="Find a list of all domain computers for the domain with the specified ID.",
        security='ApiKeyAuth'
             )
def get_ad_computer_by_domain_list(domain_id):
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




@bp.get("/computer/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADComputerSchema(many=True),
           description="List of Active Directory computer from all imported domains.")
@bp.doc(description="Returns a list of Active Directory computer from all imported domains.",
        summary="Find a list of Active Directory computer from all imported domains.",
        security='ApiKeyAuth'
             )
def get_ad_computer_list():
    return ADComputer.query.all()




@bp.post("/computer/by-spn/")
@bp.auth_required(auth)
@bp.input(schema=ADComputerBySPNSchema)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADComputerSchema(many=True),
           description="List of Active Directory computer with specified SPN")
@bp.doc(description="Returns a list of Active Directory computer with specified SPN",
        summary="Find a list of Active Directory computer with specified SPN",
        security='ApiKeyAuth'
             )
def get_ad_computer_by_spn_list(search_data):

    filters = []

    if "SPN" in search_data:
        if len(search_data['SPN']) > 0:
            filters.append(ADSPN.Name.ilike("%" + search_data['SPN'] + "%"))
    if "NOT_SPN" in search_data:
        if len(search_data['NOT_SPN']) > 0:
            filters.append(ADSPN.Name.notilike("%" + search_data['NOT_SPN'] + "%"))

    if "Domain" in search_data:
        if len (search_data["Domain"]) > 0:
            spns = ADSPN.query.filter(and_(*filters)).join(ADComputer).join(
                ADDomain).filter(ADDomain.Name.ilike("%" + search_data["Domain"] + "%")).all()
    else:
        spns = ADSPN.query.filter(and_(*filters)).all()

    result = [c.Computer for c in spns]
    return result

