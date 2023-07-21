from systemdb.webapp.api.sysinfo.schemas.responses.hosts import HostNestedSchema
from systemdb.webapp.api.ma import ma
from systemdb.core.models.eol import EoL


class EoLSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = EoL
        include_fk = True


class EoLMatchSchema(ma.Schema):

    Eol = ma.Nested(EoLSchema, many=False, allow_none=True)
    Hosts = ma.Nested(HostNestedSchema, many=True, allow_none=True)
