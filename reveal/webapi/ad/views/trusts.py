from http import HTTPStatus
from apiflask import HTTPError
from sqlalchemy import and_

from reveal.core.models.activedirectory import ADDomain
from reveal.core.models.activedirectory import ADTrust

from reveal.webapi.ad import bp
from reveal.webapi.extentions import auth

from reveal.webapi.ad.schemas.arguments.trusts import TrustSearchSchema
from reveal.webapi.ad.schemas.responses.domain import ADTrustSchema


@bp.get("/trusts/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADTrustSchema(many=True),
           description="List all imported domain trusts.")
@bp.doc(description="Returns a list of all imported domain trusts.",
        summary="Find a list of all imported domain trusts.",
        security='ApiKeyAuth')
def get_trusts():
    return ADTrust.query.all()


@bp.get("/trusts/<int:id>")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ADTrustSchema(many=False), description="AD trust.")
@bp.doc(description="Returns a domain trust stored under the specified ID.",
        summary="Find a domain trust stored under the specified ID.",
        security='ApiKeyAuth')
def get_trust_detail(id):
    try:
        return ADTrust.query.filter(ADTrust.id == id).first()
    except:
        return HTTPError(404, "ADTrust not found.")


@bp.get("/domain/<int:domain_id>/trusts/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADTrustSchema(many=True),
           description="List of password policies in the domain. ")
@bp.doc(description="Returns a list of all password policies (default and fine grained) for the domain with the "
                    "specified ID.",
        summary="Find a list of all password policies for the domain with the specified ID.",
        security='ApiKeyAuth')
def get_domain_trust_list(domain_id):
    domain = ADDomain.query.filter(ADDomain.id == domain_id).first_or_404(description="Domain not found.")
    return domain.Trusts


@bp.post("/trusts/search/")
@bp.auth_required(auth)
@bp.input(schema=TrustSearchSchema)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADTrustSchema(many=True),
           description="List of password policies in the domain. ")
@bp.doc(description="Returns a list of all password policies (default and fine grained) for the domain with the "
                    "specified ID.",
        summary="Find a list of all password policies for the domain with the specified ID.",
        security='ApiKeyAuth')
def post_trust_search(search_data):
    filters = []

    if "Source" in search_data:
        if "InvertSource" in search_data:
            filters.append(ADTrust.Source.notilike("%" + search_data['Source'] + "%"))
        else:
            filters.append(ADTrust.Source.ilike("%" + search_data['Source'] + "%"))
    if "Target" in search_data:
        if "InvertTarget" in search_data:
            filters.append(ADTrust.Target.notilike("%" + search_data['Target'] + "%"))
        else:
            filters.append(ADTrust.Target.ilike("%" + search_data['Target'] + "%"))
    if "Direction" in search_data:
        if "InvertDirection" in search_data:
            filters.append(ADTrust.Direction.notilike("%" + search_data['Direction'] + "%"))
        else:
            filters.append(ADTrust.Direction.ilike("%" + search_data['Direction'] + "%"))
    if "DistinguishedName" in search_data:
        if "InvertDistinguishedName" in search_data:
            filters.append(ADTrust.DistinguishedName.notilike("%" + search_data['DistinguishedName'] + "%"))
        else:
            filters.append(ADTrust.DistinguishedName.ilike("%" + search_data['DistinguishedName'] + "%"))

    if "UplevelOnly" in search_data:
        filters.append(ADTrust.UplevelOnly == search_data['DistinguishedName'])
    if "UsesAESKeys" in search_data:
        filters.append(ADTrust.UsesAESKeys == search_data['UsesAESKeys'])
    if "UsesRC4Encryption" in search_data:
        filters.append(ADTrust.UsesRC4Encryption == search_data['UsesRC4Encryption'])
    if "TGTDelegation" in search_data:
        filters.append(ADTrust.TGTDelegation == search_data['TGTDelegation'])
    if "SIDFilteringForestAware" in search_data:
        filters.append(ADTrust.SIDFilteringForestAware == search_data['SIDFilteringForestAware'])
    if "SIDFilteringQuarantined" in search_data:
        filters.append(ADTrust.SIDFilteringQuarantined == search_data['SIDFilteringQuarantined'])
    if "SelectiveAuthentication" in search_data:
        filters.append(ADTrust.SelectiveAuthentication == search_data['SelectiveAuthentication'])
    if "DisallowTransivity" in search_data:
        filters.append(ADTrust.DisallowTransivity == search_data['DisallowTransivity'])
    if "IntraForest" in search_data:
        filters.append(ADTrust.IntraForest == search_data['IntraForest'])
    if "IsTreeParent" in search_data:
        filters.append(ADTrust.IsTreeParent == search_data['IsTreeParent'])
    if "IsTreeRoot" in search_data:
        filters.append(ADTrust.IsTreeRoot == search_data['IsTreeRoot'])
    if "UplevelOnly" in search_data:
        filters.append(ADTrust.UplevelOnly == search_data['DistinguishedName'])

    trusts = ADTrust.query.filter(and_(*filters)).all()
    return trusts
