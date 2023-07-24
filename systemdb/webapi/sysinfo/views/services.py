from http import HTTPStatus

from systemdb.core.models.sysinfo import Service

from systemdb.webapi.sysinfo.views import bp
from systemdb.webapi.extentions import auth

from systemdb.webapi.sysinfo.schemas.responses.services import ServiceSchema


@bp.get("/hosts/<int:host_id>/services/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ServiceSchema(many=True))
@bp.doc(description="Returns a list of all installed services from a specific host.",
        summary="Find all services of a specific host",
        security='ApiKeyAuth')
def get_service_by_host(host_id):
    return Service.query.filter(Service.Host_id == host_id).all()

