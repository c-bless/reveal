from ....ma import ma
from .....models.sysinfo import Host, NetIPAddress, Hotfix, User, Group, PSInstalledVersions

class NetIPAddressNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = NetIPAddress
        include_fk = False


class HotfixNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Hotfix
        include_fk = False
        fields = ("id", "HotfixId")


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True


class UserNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = False
        fields = ("id", "Domain", "Name", "SID", "Disabled")


class GroupSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Group
        include_fk = True


class GroupNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Group
        include_fk = False
        fields = ("id", "Caption", "Name", "SID")


class HostSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Host
        include_relationships = False
        load_instance = True
        include_fk = True

    NetIPAddresses = ma.Nested(NetIPAddressNestedSchema, many=True, allow_none=True)
    Hotfixes = ma.Nested(HotfixNestedSchema, many=True, allow_none=True)
    Users = ma.Nested(UserNestedSchema, many=True, allow_none=True)
    Groups = ma.Nested(GroupNestedSchema, many=True, allow_none=True)