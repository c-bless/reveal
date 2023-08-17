from http import HTTPStatus
from sqlalchemy import and_
from apiflask import HTTPError

from systemdb.core.models.activedirectory import ADGroup
from systemdb.core.models.activedirectory import ADForest
from systemdb.core.models.activedirectory import ADDomain
from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.ad.schemas.arguments.groups import GroupNameSearchSchema
from systemdb.webapi.ad.schemas.responses.domain import ADGroupWithMembersSchema
from systemdb.webapi.ad.schemas.responses.domain import ADGroupSchema


@bp.get("/domain/<int:domain_id>/groups/domainadmins/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema,
           description="Domain Admin group")
@bp.doc(description="Returns the domain admin group for the specified domain.",
        summary="Find the domain admin group for the specified domain.",
        security='ApiKeyAuth'
        )
def get_domain_admins_for_domain(domain_id: int):
    try:
        return ADGroup.query.filter(
            and_(ADGroup.Domain_id == domain_id, ADGroup.SID == SID_LOCAL_ADMIN_GROUP)).first()
    except:
        return HTTPError(404, "Domain/Group not found.")


@bp.post("/groups/by-name/")
@bp.auth_required(auth)
@bp.input(schema=GroupNameSearchSchema, location="json")
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema(many=True),
           description="Group with nested member objects.")
@bp.doc(description="Returns all groups that matches the name. If the id is also present in the search parameters "
                    "both values will be used.",
        summary="Find all domains that match the group name.",
        security='ApiKeyAuth'
        )
def get_group_by_name(search_data):
    if "id" in search_data:
        groups = ADGroup.query.filter(
            and_(ADGroup.SamAccountName.ilike("%" + search_data['name'] + "%"),
                 ADGroup.Domain_id == search_data['id'])).all()
        return groups
    else:
        return ADGroup.query.filter(ADGroup.SamAccountName.ilike("%" + search_data['name'] + "%")).all()


@bp.get("/domain/<int:domain_id>/groups/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupSchema(many=True),
           description="List of groups in the domain. If no groups are assigned to the domain an empty list is returned")
@bp.doc(description="Returns a list of all domain groups for the domain with the specified ID.",
        summary="Find a list of all domain groups for the domain with the specified ID.",
        security='ApiKeyAuth'
        )
def get_domain_group_list(domain_id):
    try:
        return ADGroup.query.filter(ADGroup.Domain_id == domain_id).all()
    except:
        return HTTPError(404, "Domain not found.")


@bp.get("/forest/<int:forest_id>/groups/enterpriseadmins/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema,
           description="Enterprise Admin group")
@bp.doc(description="Returns the enterprise admin group for the specified forest.",
        summary="Find the enterprise admin group for the specified forest.",
        security='ApiKeyAuth'
        )
def get_ad_enterpriseadmin_group(forest_id):
    try:
        forest = ADForest.query.get_or_404(forest_id)
        domains = ADDomain.query.filter(ADDomain.DNSRoot == forest.Name).all()
        ids = [d.id for d in domains]
        return ADGroup.query.filter(
            and_(ADGroup.SamAccountName == "Enterprise Admins", ADDomain.id.in_(ids))).first()
    except:
        return HTTPError(404, "Domain/Group not found.")
