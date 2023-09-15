from http import HTTPStatus
from sqlalchemy import and_
from apiflask import HTTPError

from systemdb.core.models.activedirectory import ADGroup
from systemdb.core.models.activedirectory import ADForest
from systemdb.core.models.activedirectory import ADDomain
from systemdb.core.sids import SID_LOCAL_ADMIN_GROUP
from systemdb.core.querries.ad import find_protected_users

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth


from systemdb.webapi.ad.schemas.arguments.groups import GroupSearchSchema
from systemdb.webapi.ad.schemas.responses.domain import ADGroupWithMembersSchema
from systemdb.webapi.ad.schemas.responses.domain import ADGroupSchema



@bp.get("/groups/<int:group_id>")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema,
           description="Group Details")
@bp.doc(description="Returns the details for the specified group including memberships.",
        summary="Find the details for the specified group including memberships",
        security='ApiKeyAuth'
        )
def get_group_details(group_id: int):
    return ADGroup.query.get_or_404(group_id)


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


@bp.post("/groups/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema(many=True),
           description="Group with nested member objects.")
@bp.doc(description="Returns all groups from all imported domains.",
        summary="Find all groups from all imported domains.",
        security='ApiKeyAuth'
        )
def get_groups():
    return ADGroup.query.all()



@bp.post("/groups/search/")
@bp.auth_required(auth)
@bp.input(schema=GroupSearchSchema, location="json")
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema(many=True),
           description="Group with nested member objects.")
@bp.doc(description="Returns all groups that matches the name. If the id is also present in the search parameters "
                    "both values will be used.",
        summary="Find all domains that match the group name.",
        security='ApiKeyAuth'
        )
def post_group_search(search_data):
    group_filter = []
    domain_filter = []
    if "id" in search_data:
        group_filter.append(ADGroup.id == int(search_data["id"]))
    if "SamAccountName" in search_data:
        if len(search_data["SamAccountName"]) > 0:
            if "InvertSamAccountName" in search_data:
                if not search_data["InvertSamAccountName"]:
                    group_filter.append(ADGroup.SamAccountName.ilike("%" + search_data["SamAccountName"] + "%"))
                else:
                    group_filter.append(ADGroup.SamAccountName.notilike("%" + search_data["SamAccountName"] + "%"))
            else:
                group_filter.append(ADGroup.SamAccountName.ilike("%" + search_data["SamAccountName"] + "%"))
    if "SID" in search_data:
        if len(search_data["SID"]) > 0:
            if "InvertSID" in search_data:
                if not search_data["InvertSID"]:
                    group_filter.append(ADGroup.SID.ilike("%" + search_data["SID"] + "%"))
                else:
                    group_filter.append(ADGroup.SID.notilike("%" + search_data["SID"] + "%"))
            else:
                group_filter.append(ADGroup.SID.ilike("%" + search_data["SID"] + "%"))
    if "Description" in search_data:
        if len(search_data["Description"]) > 0:
            if "InvertDescription" in search_data:
                if not search_data["InvertDescription"]:
                    group_filter.append(ADGroup.Description.ilike("%" + search_data["Description"] + "%"))
                else:
                    group_filter.append(ADGroup.Description.notilike("%" + search_data["Description"] + "%"))
            else:
                group_filter.append(ADGroup.Description.ilike("%" + search_data["Description"] + "%"))
    if "GroupCategory" in search_data:
        if len(search_data["GroupCategory"]) > 0:
            if "InvertGroupCategory" in search_data:
                if not search_data["InvertGroupCategory"]:
                    group_filter.append(ADGroup.GroupCategory.ilike("%" + search_data["GroupCategory"] + "%"))
                else:
                    group_filter.append(ADGroup.GroupCategory.notilike("%" + search_data["GroupCategory"] + "%"))
            else:
                group_filter.append(ADGroup.GroupCategory.ilike("%" + search_data["GroupCategory"] + "%"))
    if "GroupScope" in search_data:
        if len(search_data["GroupScope"]) > 0:
            if "InvertGroupScope" in search_data:
                if not search_data["InvertGroupScope"]:
                    group_filter.append(ADGroup.GroupScope.ilike("%" + search_data["GroupScope"] + "%"))
                else:
                    group_filter.append(ADGroup.GroupScope.notilike("%" + search_data["GroupScope"] + "%"))
            else:
                group_filter.append(ADGroup.GroupScope.ilike("%" + search_data["GroupScope"] + "%"))
    if "Domain" in search_data:
        if len(search_data["Domain"]) > 0:
            if "InvertDomain" in search_data:
                if not search_data["InvertDomain"]:
                    group_filter.append(ADDomain.Name.ilike("%" + search_data["Domain"] + "%"))
                else:
                    group_filter.append(ADDomain.Name.notilike("%" + search_data["Domain"] + "%"))
            else:
                group_filter.append(ADDomain.Name.ilike("%" + search_data["Domain"] + "%"))
    return ADGroup.query.filter(and_(*group_filter)).join(ADDomain).filter(and_(*domain_filter)).all()



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



@bp.get("/groups/protectedusers/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema(many=True),
           description="List of members of the 'protected users' groups across all imported domains / forest.")
@bp.doc(description="Returns a list of members of the 'protected users' groups across all imported domains / forest.",
        summary="Find a list of members of the 'protected users' groups across all imported domains / forest.",
        security='ApiKeyAuth')
def get_protected_users_group_list():
    groups = find_protected_users()
    print(groups)
    return groups