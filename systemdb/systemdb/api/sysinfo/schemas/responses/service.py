from ....ma import ma
from .....models.sysinfo import Service, ServiceACL


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
