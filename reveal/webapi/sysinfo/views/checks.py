from http import HTTPStatus

from reveal.core.models.sysinfo import RegistryCheck
from reveal.core.models.sysinfo import ConfigCheck

from reveal.webapi.sysinfo.views import bp
from reveal.webapi.extentions import auth


from reveal.webapi.sysinfo.schemas.arguments.checks import RegistryCheckByNameSearchSchema
from reveal.webapi.sysinfo.schemas.responses.checks import RegistryCheckSchema
from reveal.webapi.sysinfo.schemas.responses.checks import RegistryCheckMatchSchema

from reveal.webapi.sysinfo.schemas.arguments.checks import ConfigCheckByNameSearchSchema
from reveal.webapi.sysinfo.schemas.responses.checks import ConfigCheckSchema
from reveal.webapi.sysinfo.schemas.responses.checks import ConfigCheckMatchSchema


@bp.get("/hosts/<int:host_id>/registrychecks/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=RegistryCheckSchema(many=True))
@bp.doc(description="Returns a list of performed additional registry checks from a specific host.",
        summary="Find all additional registry checks of a specific host",
        security='ApiKeyAuth')
def get_registrychecks_by_host(host_id):
    return RegistryCheck.query.filter(RegistryCheck.Host_id == host_id).all()


@bp.post("/registrychecks/by-name/")
@bp.auth_required(auth)
@bp.input(schema=RegistryCheckByNameSearchSchema, location='json')
@bp.output(status_code=HTTPStatus.OK, schema=RegistryCheckMatchSchema(many=True))
@bp.doc(description="Returns a list of performed registry checks and corresponding hosts where the RegistryCheck "
                    "contains the specified name.",
        summary="Find all registry checks across all hosts where the RegistryCheck contains the specified name.",
        security='ApiKeyAuth')
def get_registrychecks_by_name(search_data):
    results = []
    checks = RegistryCheck.find_by_name(name=search_data['Name'])
    for c in checks:
        rcms = RegistryCheckMatchSchema()
        rcms.RegistryCheck = c
        rcms.Host = c.Host
        results.append(rcms)
    return results


@bp.get("/hosts/<int:host_id>/configchecks/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK,
           schema=ConfigCheckSchema(many=True))
@bp.doc(description="Return a list of performed config checks of a specific host.",
        summary="Find all performed config checks on a specific host",
        security='ApiKeyAuth')
def get_configchecks_by_host(host_id):
    return ConfigCheck.query.filter(ConfigCheck.Host_id == host_id).all()


@bp.post("/configchecks/by-name/")
@bp.auth_required(auth)
@bp.input(schema=ConfigCheckByNameSearchSchema, location='json')
@bp.output(status_code=HTTPStatus.OK, schema=ConfigCheckMatchSchema(many=True))
@bp.doc(description="Returns a list of performed config checks and corresponding hosts where the ConfigCheck "
                    "contains the specified name.",
        summary="Find all config checks across all hosts where the ConfigCheck contains the specified name.",
        security='ApiKeyAuth')
def get_configchecks_by_name(search_data):
    results = []
    checks = ConfigCheck.find_by_name(name=search_data['Name'])
    for c in checks:
        rcms = ConfigCheckMatchSchema()
        rcms.ConfigCheck = c
        rcms.Host = c.Host
        results.append(rcms)
    return results

