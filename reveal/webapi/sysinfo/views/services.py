from http import HTTPStatus

from reveal.webapi.sysinfo.views import bp
from reveal.webapi.extentions import auth

from reveal.core.models.sysinfo import Service
from reveal.core.models.sysinfo import ServiceACL
from reveal.webapi.sysinfo.schemas.arguments.services import ServicePermissionSearchSchema
from reveal.webapi.sysinfo.schemas.responses.services import ServiceSchema
from reveal.webapi.sysinfo.schemas.responses.services import ServiceACLSchema

@bp.get("/hosts/<int:host_id>/services/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ServiceSchema(many=True))
@bp.doc(description="Returns a list of all installed services from a specific host.",
        summary="Find all services of a specific host",
        security='ApiKeyAuth')
def get_service_by_host(host_id):
    return Service.query.filter(Service.Host_id == host_id).all()


@bp.get("/services/<int:service_id>")
@bp.auth_required(auth)
@bp.doc(description="Return a service based on specified ID",
        summary="Find service by ID",
        security='ApiKeyAuth')
@bp.output(status_code=HTTPStatus.OK, schema=ServiceSchema)
def get_service_by_id(id):
    return Service.query.get_or_404(id)


@bp.get("/services/")
@bp.auth_required(auth)
@bp.doc(description="Returns a list of all installed services from all hosts.",
        summary="Find all services",
        security='ApiKeyAuth')
@bp.output(status_code=HTTPStatus.OK, schema=ServiceSchema(many=True))
def get_service_list():
    return Service.query.all()


@bp.get("/services/acls/")
@bp.auth_required(auth)
@bp.doc(description="Returns a list of all ACLs for services from all hosts.",
        summary="Find all services ACLs",
        security='ApiKeyAuth')
@bp.output(status_code=HTTPStatus.OK, schema=ServiceACLSchema(many=True))
def get_service_acl_list():
    return ServiceACL.query.all()


@bp.post("/services/acls/by-permission/")
@bp.auth_required(auth)
@bp.doc(description="Returns a list of all ACLs for services based on specified search filter",
         summary="Find product by permission",
    security='ApiKeyAuth')
@bp.input(schema=ServicePermissionSearchSchema, location="json")
@bp.output(status_code=HTTPStatus.OK, schema=ServiceACLSchema(many=True))
def get_service_acls_by_permission(search_data):
    services = ServiceACL.query.filter(and_(ServiceACL.AccountName.like("%" + search_data['Accountname'] + "%"),
                                            ServiceACL.AccessRight.like("%" + search_data['Permission'] + "%")
                                            )).all()
    return services

