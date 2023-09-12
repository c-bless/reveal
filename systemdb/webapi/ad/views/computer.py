from http import HTTPStatus
from apiflask import HTTPError
from sqlalchemy import and_

from systemdb.core.models.activedirectory import ADComputer
from systemdb.core.models.activedirectory import ADDomainController
from systemdb.core.models.activedirectory import ADSPN
from systemdb.core.models.activedirectory import ADDomain
from systemdb.core.models.activedirectory import ADOperationMasterRole

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.ad.schemas.responses.domain import ADComputerSchema
from systemdb.webapi.ad.schemas.arguments.computer import ADComputerBySPNSchema
from systemdb.webapi.ad.schemas.arguments.computer import ADComputerSearchSchema
from systemdb.webapi.ad.schemas.arguments.computer import ADComputerByDomainSearchSchema
from systemdb.webapi.ad.schemas.arguments.computer import ADDCSearchSchema
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




@bp.post("/computer/search/")
@bp.auth_required(auth)
@bp.input(schema=ADComputerSearchSchema)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADComputerSchema(many=True),
           description="List of Active Directory computer matching specified filters")
@bp.doc(description="Returns a list of Active Directory computer matching specified filters",
        summary="Find a list of Active Directory computer matching specified filters",
        security='ApiKeyAuth'
             )
def post_ad_computer_search(search_data):

    filters = []

    if "Description" in search_data:
        if len(search_data['Description']) > 0:
            filters.append(ADComputer.Description.ilike("%" + search_data['Description'] + "%"))
    if "DNSHostName" in search_data:
        if len(search_data['DNSHostName']) > 0:
            filters.append(ADComputer.DNSHostName.ilike("%" + search_data['DNSHostName'] + "%"))
    if "DistinguishedName" in search_data:
        if len(search_data['DistinguishedName']) > 0:
            filters.append(ADComputer.DistinguishedName.ilike("%" + search_data['DistinguishedName'] + "%"))
    if "OperatingSystem" in search_data:
        if len(search_data['OperatingSystem']) > 0:
            filters.append(ADComputer.OperatingSystem.ilike("%" + search_data['OperatingSystem'] + "%"))
    if "PrimaryGroup" in search_data:
        if len(search_data['PrimaryGroup']) > 0:
            filters.append(ADComputer.PrimaryGroup.ilike("%" + search_data['PrimaryGroup'] + "%"))
    if "SID" in search_data:
        if len(search_data['SID']) > 0:
            filters.append(ADComputer.SID.ilike("%" + search_data['SID'] + "%"))
    if "SamAccountName" in search_data:
        if len(search_data['SamAccountName']) > 0:
            filters.append(ADComputer.SamAccountName.ilike("%" + search_data['SamAccountName'] + "%"))
    if "IPv4Address" in search_data:
        if len(search_data['IPv4Address']) > 0:
            filters.append(ADComputer.IPv4Address.ilike("%" + search_data['IPv4Address'] + "%"))
    if "IPv6Address" in search_data:
        if len(search_data['IPv6Address']) > 0:
            filters.append(ADComputer.IPv6Address.ilike("%" + search_data['IPv6Address'] + "%"))
    if "Id" in search_data:
        if len(search_data['Id']) > 0:
            filters.append(ADComputer.id == int(search_data['Id']))
    if "Enabled" in search_data:
        if search_data["Enabled"]:
            filters.append(ADComputer.Enabled == True)
        else:
            filters.append(ADComputer.Enabled == False)
    if "TrustedForDelegation" in search_data:
        if search_data["TrustedForDelegation"]:
            filters.append(ADComputer.TrustedForDelegation == True)
        else:
            filters.append(ADComputer.TrustedForDelegation == False)
    if "TrustedToAuthForDelegation" in search_data:
        if search_data["TrustedToAuthForDelegation"]:
            filters.append(ADComputer.TrustedToAuthForDelegation == True)
        else:
            filters.append(ADComputer.TrustedToAuthForDelegation == False)
    if "Domain" in search_data:
        if len (search_data["Domain"]) > 0:
            computer_list = ADComputer.query.filter(and_(*filters)).join(
                ADDomain).filter(ADDomain.Name.ilike("%" + search_data["Domain"] + "%")).all()
    else:
        computer_list = ADComputer.query.filter(and_(*filters)).all()

    return computer_list


@bp.post("/computer/by-domain/")
@bp.auth_required(auth)
@bp.input(schema=ADComputerByDomainSearchSchema)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADComputerSchema(many=True),
           description="List of Active Directory computer with specified Domain")
@bp.doc(description="Returns a list of Active Directory computer with specified Domain",
        summary="Find a list of Active Directory computer with specified Domain",
        security='ApiKeyAuth'
             )
def post_ad_computer_by_domain(search_data):

    filters = []

    if "NETBIOS" in search_data:
        if len(search_data['NETBIOS']) > 0:
            if "InvertNETBIOS" in search_data and search_data["InvertNETBIOS"] == True:
                filters.append(ADDomain.NetBIOSName.notilike("%" + search_data['NETBIOS'] + "%"))
            else:
                filters.append(ADDomain.NetBIOSName.ilike("%" + search_data['NETBIOS'] + "%"))
    if "Domain" in search_data:
        if len(search_data['Domain']) > 0:
            if "InvertDomain" in search_data and search_data["InvertDomain"] == True:
                filters.append(ADDomain.Name.notilike("%" + search_data['Domain'] + "%"))
            else:
                filters.append(ADDomain.Name.ilike("%" + search_data['Domain'] + "%"))
    if "DomainId" in search_data:
        if len(search_data['DomainId']) > 0:
            if "InvertDomainId" in search_data and search_data["InvertDomainId"] == True:
                filters.append(ADDomain.id != int(search_data['DomainId']))
            else:
                filters.append(ADDomain.id == int(search_data['DomainId']))

    domains = ADDomain.query.filter(and_(*filters)).all()

    result = []
    for d in domains:
        for c in d.ComputerList:
            result.append(c)
    return result


@bp.get("/DCs/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ADDomainControllerSchema(many=True),
           description="List of DCs across all domains. If no DCs are found an empty list is returned")
@bp.doc(description="Returns a list DCs across all domains. If no DCs are found an empty list is returned",
        summary="Find a list DCs across all domains. If no DCs are found an empty list is returned",
        security='ApiKeyAuth'
         )
def get_dc_list():
    return ADDomainController.query.all()


@bp.post("/DCs/search")
@bp.auth_required(auth)
@bp.input(schema=ADDCSearchSchema)
@bp.output(status_code=HTTPStatus.OK, schema=ADDomainControllerSchema(many=True),
           description="List of DCs across all domains. If no DCs are found an empty list is returned")
@bp.doc(description="Returns a list DCs across all domains. If no DCs are found an empty list is returned",
        summary="Find a list DCs across all domains. If no DCs are found an empty list is returned",
        security='ApiKeyAuth'
         )
def post_dc_search_list(search_data):
    dc_filter = []

    if "Name" in search_data:
        if len(search_data['Name']) > 0:
            if "InvertName" in search_data:
                if not search_data["InvertName"]:
                    dc_filter.append(ADDomainController.Name.ilike("%" + search_data['InvertName'] + "%"))
                else:
                    dc_filter.append(ADDomainController.Name.notilike("%" + search_data['InvertName'] + "%"))
            else:
                dc_filter.append(ADDomainController.Name.ilike("%" + search_data['InvertName'] + "%"))
    if "OperatingSystem" in search_data:
        if len(search_data['OperatingSystem']) > 0:
            if "InvertOperatingSystem" in search_data:
                if not search_data["InvertOperatingSystem"]:
                    dc_filter.append(ADDomainController.OperatingSystem.ilike("%" + search_data['OperatingSystem'] + "%"))
                else:
                    dc_filter.append(ADDomainController.OperatingSystem.notilike("%" + search_data['OperatingSystem'] + "%"))
            else:
                dc_filter.append(ADDomainController.OperatingSystem.ilike("%" + search_data['OperatingSystem'] + "%"))
    if "IPv4Address" in search_data:
        if len(search_data['IPv4Address']) > 0:
            if "InvertIPv4Address" in search_data:
                if not search_data["InvertIPv4Address"]:
                    dc_filter.append(ADDomainController.IPv4Address.ilike("%" + search_data['IPv4Address'] + "%"))
                else:
                    dc_filter.append(ADDomainController.IPv4Address.notilike("%" + search_data['IPv4Address'] + "%"))
            else:
                dc_filter.append(ADDomainController.IPv4Address.ilike("%" + search_data['IPv4Address'] + "%"))
    if "IPv6Address" in search_data:
        if len(search_data['IPv6Address']) > 0:
            if "InvertIPv6Address" in search_data:
                if not search_data["InvertIPv6Address"]:
                    dc_filter.append(ADDomainController.IPv6Address.ilike("%" + search_data['IPv6Address'] + "%"))
                else:
                    dc_filter.append(ADDomainController.IPv6Address.notilike("%" + search_data['IPv6Address'] + "%"))
            else:
                dc_filter.append(ADDomainController.IPv6Address.ilike("%" + search_data['IPv6Address'] + "%"))
    if "UseIsGlobalCatalog" in search_data:
        if search_data["UseIsGlobalCatalog"]:
            dc_filter.append(ADDomainController.UseIsGlobalCatalog == search_data['IsGlobalCatalog'])
    if "UseEnabled" in search_data:
        if search_data["UseEnabled"]:
            dc_filter.append(ADDomainController.Enabled == search_data['Enabled'])
    if "Domain" in search_data:
        if len(search_data['Domain']) > 0:
            if "InvertDomain" in search_data:
                if not search_data["InvertDomain"]:
                    ids = [d.id for d in ADDomain.query.filter(ADDomain.Name.ilike("%" + search_data['Domain'] + "%")).all()]
                    dc_filter.append(ADDomainController.Domain_id.in_(ids))
                else:
                    ids = [d.id for d in ADDomain.query.filter(ADDomain.Name.notilike("%" + search_data['Domain'] + "%")).all()]
                    dc_filter.append(ADDomainController.Domain_id.in_(ids))
            else:
                ids = [d.id for d in ADDomain.query.filter(ADDomain.Name.notilike("%" + search_data['Domain'] + "%")).all()]
                dc_filter.append(ADDomainController.Domain_id.in_(ids))

    return ADDomainController.query.filter(and_(*dc_filter)).all()