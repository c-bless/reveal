from ...ma import ma
from ....models.sysinfo import Host, NetIPAddress, Hotfix

class NetIPAddressNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = NetIPAddress
        include_fk = False


class HotfixNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Hotfix
        include_fk = False
        fields = ("id", "HotfixId")

class HostSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Host
        include_relationships = False
        load_instance = True
        include_fk = True

    NetIPAddresses = ma.Nested(NetIPAddressNestedSchema, many=True, allow_none=True)
    Hotfixes = ma.Nested(HotfixNestedSchema, many=True, allow_none=True)

host_schema = HostSchema()
hosts_schema = HostSchema(many=True)
