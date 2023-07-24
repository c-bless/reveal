from http import HTTPStatus

from systemdb.core.models.sysinfo import RegistryCheck

from systemdb.webapi.sysinfo.views import bp
from systemdb.webapi.extentions import auth


from systemdb.webapi.sysinfo.schemas.arguments.checks import RegistryCheckByNameSearchSchema
from systemdb.webapi.sysinfo.schemas.responses.checks import RegistryCheckSchema
from systemdb.webapi.sysinfo.schemas.responses.checks import RegistryCheckMatchSchema


@bp.get("/registrychecks/by-host/<int:host_id>")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=RegistryCheckSchema(many=True))
@bp.doc(description="Returns a list of performed additional registry checks from a specific host.",
        summary="Find all additional registry checks of a specific host",
        security='ApiKeyAuth')
def get_registrycheck_by_host(host_id):
    return RegistryCheck.query.filter(RegistryCheck.Host_id == host_id).all()


@bp.post("/registrychecks/by-Name/")
@bp.auth_required(auth)
@bp.input(schema=RegistryCheckByNameSearchSchema, location='json')
@bp.output(status_code=HTTPStatus.OK, schema=RegistryCheckMatchSchema(many=True))
@bp.doc(description="Returns a list of performed registry checks and corresponding hosts where the RegistryCheck "
                    "contains the specified name.",
        summary="Find all registry checks across all hosts where the RegistryCheck contains the specified name.",
        security='ApiKeyAuth')
def get_registrycheck_by_name(search_data):
    results = []
    checks = RegistryCheck.find_by_name(name=search_data['Name'])
    for c in checks:
        rcms = RegistryCheckMatchSchema()
        rcms.RegistryCheck = c
        rcms.Host = RegistryCheck.Host
        results.append(rcms)
    print(results)
    return results
