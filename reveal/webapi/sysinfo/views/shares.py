from http import HTTPStatus

from reveal.webapi.sysinfo.views import bp
from reveal.webapi.extentions import auth

from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import Share
from reveal.webapi.sysinfo.schemas.responses.hosts import ShareSchema
from reveal.webapi.sysinfo.schemas.responses.hosts import ShareDetailSchema

@bp.get("/hosts/<int:host_id>/shares/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ShareSchema(many=True))
@bp.doc(description="Returns a list of all available shares on the specified host",
        summary="Find all available shares on the specified host",
        security='ApiKeyAuth')
def get_shares_by_host(host_id):
    host = Host.query.get_or_404(host_id)
    return host.Shares


@bp.get("/shares/")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ShareSchema(many=True))
@bp.doc(description="Returns a list of all available share across all imported hosts",
        summary="Find a list of all available share across all imported hosts",
        security='ApiKeyAuth')
def get_shares():
    return Share.query.all()


@bp.get("/shares/<int:share_id>")
@bp.auth_required(auth)
@bp.output(status_code=HTTPStatus.OK, schema=ShareDetailSchema(many=False))
@bp.doc(description="Returns details about a specific share.",
        summary="Find details about a specific share.",
        security='ApiKeyAuth')
def get_share_details(share_id):
    share = Share.query.filter(Share.id == share_id).first()
    return share

