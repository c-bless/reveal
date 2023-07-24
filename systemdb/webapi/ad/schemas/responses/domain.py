from systemdb.webapi.extentions import ma
from systemdb.core.models.activedirectory import ADDomain
from systemdb.core.models.activedirectory import ADTrust
from systemdb.core.models.activedirectory import ADForest
from systemdb.core.models.activedirectory import ADUser
from systemdb.core.models.activedirectory import ADSPN
from systemdb.core.models.activedirectory import ADComputer
from systemdb.core.models.activedirectory import ADDomainController
from systemdb.core.models.activedirectory import ADGroup
from systemdb.core.models.activedirectory import ADDCServerRole
from systemdb.core.models.activedirectory import ADUserMembership
from systemdb.core.models.activedirectory import ADGroupMember
from systemdb.core.models.activedirectory import ADForestSite
from systemdb.core.models.activedirectory import ADOperationMasterRole
from systemdb.core.models.activedirectory import ADForestGlobalCatalog
from systemdb.core.models.activedirectory import ADPasswordPolicy


class ADDomainSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADDomain
        include_fk = True


class ADOperationMasterRoleSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADOperationMasterRole
        include_fk = True


class ADForestGlobalCatalogSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADForestGlobalCatalog
        include_fk = True


class ADForestSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADForest
        include_fk = True

    GlobalCatalogs = ma.Nested(ADForestGlobalCatalogSchema, many=True, allow_none=True)


class ADTrustSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADTrust
        include_fk = True


class ADUserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADUser
        include_fk = True


class ADGroupMemberSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADGroupMember
        include_fk = True


class ADGroupSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADGroup
        include_fk = True


class ADGroupWithMembersSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADGroup
        include_fk = True

    Members = ma.Nested(ADGroupMemberSchema, many=True, allow_none=True)

class ADSPNSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADSPN
        include_fk = True


class ADComputerSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADComputer
        include_fk = True


class ADDomainControllerSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADDomainController
        include_fk = True

    ADOperationMasterRole = ma.Nested(ADOperationMasterRoleSchema, many=True, allow_none=True)


class ADDCServerRoleSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADDCServerRole
        include_fk = True


class ADUserMembershipSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADUserMembership
        include_fk = True


class ADGroupMemberSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADGroupMember
        include_fk =True

class ADForestSiteSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADForestSite
        include_fk = True


class ADPasswordPolicySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADPasswordPolicy
        include_fk =True