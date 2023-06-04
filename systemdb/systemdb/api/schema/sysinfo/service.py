from ...ma import ma
from ....models.sysinfo import Service, ServiceACL


class ServiceACLSchema(ma.SQLAlchemyAutoSchema):
    """
    Service ACL
    """
    class Meta:
        model = ServiceACL
        load_instance = True
        include_fk = True

serviceACL_schema = ServiceACLSchema()
serviceACLs_schema = ServiceACLSchema(many=True)


class ServiceSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Service
        include_relationships = True
        load_instance = True
        include_fk = True
        exclude = ("BinaryPermissionsStr",)

    BinaryPermissions = ma.Nested(ServiceACLSchema, many=True, allow_none=True)

service_schema = ServiceSchema()
services_schema = ServiceSchema(many=True)

