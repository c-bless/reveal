from reveal.webapi.extentions import ma
from flask_marshmallow.fields import fields

from reveal.core.models.sysinfo import Host, NetIPAddress, Hotfix, User, Group, PSInstalledVersions, \
    NetAdapter, DefenderSettings, Printer, ConfigCheck, Share, ShareACL, ShareACLNTFS, GroupMember


class PSInstalledVersionsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = PSInstalledVersions
        include_fk = True


class PrinterSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Printer
        include_fk = True


class DefenderSettingSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = DefenderSettings
        include_fk = True


class ConfigCheckSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ConfigCheck
        include_fk = True


class NetAdapterSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = NetAdapter
        include_fk = True


class NetIPAddressSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = NetIPAddress
        include_fk = True


class NetIPAddressNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = NetIPAddress
        include_fk = False


class HotfixSchema(ma.SQLAlchemyAutoSchema):

    class Meta:
        model = Hotfix
        include_fk = True


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

class GroupMemberNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = GroupMember
        include_fk = False
        fields = ("id", "Caption", "Name", "SID", "Domain", "AccountType")

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


class HostNestedSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Host
        include_fk = False
        fields = ("id", "Hostname", "Domain", "OSVersion", "OSBuildNumber", "OSProductType", "OSName",
                  "SystemGroup", "Location")


class PrinterMatchSchema(ma.Schema):

    Printer = fields.String(allow_none=False)
    Hosts = ma.Nested(HostNestedSchema, many=True, allow_none=True)



class ShareACLSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ShareACL
        include_fk = True


class ShareACLNTFSSchema(ma.SQLAlchemyAutoSchema):

    class Meta:
        model = ShareACLNTFS
        include_fk = True


class ShareSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Share
        include_fk = True


class ShareDetailSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Share

    ShareACLNTFS = ma.Nested(ShareACLSchema, many=True, allow_none=True)
    NTFSPermissions = ma.Nested(ShareACLNTFSSchema, many=True, allow_none=True)