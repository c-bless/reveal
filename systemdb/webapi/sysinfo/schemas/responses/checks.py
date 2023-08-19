from systemdb.webapi.sysinfo.schemas.responses.hosts import HostNestedSchema
from systemdb.webapi.extentions import ma
from systemdb.core.models.sysinfo import RegistryCheck
from systemdb.core.models.sysinfo import ConfigCheck


from apiflask.schemas import Schema


class RegistryCheckSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = RegistryCheck
        include_fk = True


class RegistryCheckMatchSchema(Schema):

    RegistryCheck = ma.Nested(RegistryCheckSchema, many=False)
    Host = ma.Nested(HostNestedSchema, many=False)


class ConfigCheckSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ConfigCheck
        include_fk = True


class ConfigCheckMatchSchema(Schema):

    ConfigCheck = ma.Nested(ConfigCheckSchema, many=False)
    Host = ma.Nested(HostNestedSchema, many=False)