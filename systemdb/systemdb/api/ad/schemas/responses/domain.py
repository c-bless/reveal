from ....ma import ma

from .....models.activedirectory import ADDomain, ADTrust, ADForest, ADUser, ADSPN, ADComputer,ADDomainController, \
    ADGroup, ADDCServerRole, ADUserMembership, ADGroupMember, ADForestSite, ADOperationMasterRole,\
    ADForestGlobalCatalog, ADPasswordPolicy


class ADDomainSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADDomain
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


class ADGroupSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADGroup
        include_fk = True


class ADSPNSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADSPN
        include_fk = True


class ADComputerSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ADComputer
        include_fk = True
