from systemdb.webapp.api.ma import ma
from systemdb.core.models.sysinfo import Service
from systemdb.core.models.sysinfo import ServiceACL


class ServiceACLSchema(ma.SQLAlchemyAutoSchema):
    """
    Service ACL
    """
    class Meta:
        model = ServiceACL
        load_instance = True
        include_fk = True

class ServiceSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Service
        include_relationships = True
        load_instance = True
        include_fk = True
        exclude = ("BinaryPermissionsStr",)

    BinaryPermissions = ma.Nested(ServiceACLSchema, many=True, allow_none=True)
