from ....ma import ma
from .....models.sysinfo import Host
from .....models.eol import EoL


class HostNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Host
        include_fk = False
        fields = ("id", "Hostname", "Domain", "OSVersion", "OSBuildNumber", "OSProductType", "OSName",
                  "SystemGroup", "Location")


class EoLSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = EoL
        include_fk = True


class EoLMatchSchema(ma.Schema):

    EolMatches = ma.Nested(EoLSchema, many=True, allow_none=True)
    Hosts = ma.Nested(HostNestedSchema, many=True, allow_none=True)
