from http import HTTPStatus
from apiflask import HTTPError

from systemdb.core.models.activedirectory import ADUser

from systemdb.webapi.ad import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.ad.schemas.responses.domain import ADGroupWithMembersSchema
from systemdb.core.querries.ad import find_domain_admin_groups
from systemdb.core.querries.ad import find_enterprise_admin_groups
from systemdb.core.querries.ad import find_schema_admin_groups

@bp.get("/groups/domadmins/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema(many=True),
           description="List of domain admin groups across all imported domains.")
@bp.doc(description="Returns a list of domain admin groups across all imported domains.",
        summary="Find a list of of domain admin groups across all imported domains.",
        security='ApiKeyAuth')
def get_domain_admin_group_list():
    return find_domain_admin_groups()


@bp.get("/groups/enterpriseadmins/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema(many=True),
           description="List of enterprise admin groups across all imported forests.")
@bp.doc(description="Returns a list of enterpriseomain admin groups across all imported forests.",
        summary="Find a list of enterpriseomain admin groups across all imported forests.",
        security='ApiKeyAuth')
def get_enterprise_admin_group_list():
    return find_enterprise_admin_groups()



@bp.get("/groups/schemaadmins/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ADGroupWithMembersSchema(many=True),
           description="List of schema admin groups across all imported domains / forest.")
@bp.doc(description="Returns a list of schema admin groups across all imported domains / forest.",
        summary="Find a list of of schema admin groups across all imported domains / forest.",
        security='ApiKeyAuth')
def get_schema_admin_group_list():
    return find_schema_admin_groups()






