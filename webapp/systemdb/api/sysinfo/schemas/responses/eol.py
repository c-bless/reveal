from webapp.systemdb.api.sysinfo.schemas.responses.hosts import HostNestedSchema
from webapp.systemdb.api.ma import ma
from webapp.systemdb.models.eol import EoL


class EoLSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = EoL
        include_fk = True


class EoLMatchSchema(ma.Schema):

    Eol = ma.Nested(EoLSchema, many=False, allow_none=True)
    Hosts = ma.Nested(HostNestedSchema, many=True, allow_none=True)
