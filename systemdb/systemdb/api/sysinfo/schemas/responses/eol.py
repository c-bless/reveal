from ....ma import ma
from .....models.sysinfo import Host
from .....models.eol import EoL
from .hosts import HostNestedSchema




class EoLSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = EoL
        include_fk = True


class EoLMatchSchema(ma.Schema):

    Eol = ma.Nested(EoLSchema, many=False, allow_none=True)
    Hosts = ma.Nested(HostNestedSchema, many=True, allow_none=True)
