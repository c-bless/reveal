from systemdb.core.extentions import db

class ADDomain(db.Model):
    __tablename__ = "ADDomain"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(1024), unique=False, nullable=False)
    NetBIOSName = db.Column(db.String(1024), unique=False, nullable=False)
    DNSRoot = db.Column(db.String(1024), unique=False)
    DomainSID = db.Column(db.String(1024), unique=True, nullable=False)
    RIDMaster = db.Column(db.String(1024), unique=False)
    PDCEmulator = db.Column(db.String(1024), unique=False)
    ParentDomain = db.Column(db.String(1024), unique=False)
    Forest = db.Column(db.String(1024), unique=False)
    UsersContainer = db.Column(db.String(), unique=False)
    SystemContainer = db.Column(db.String(), unique=False)
    ComputerContainer = db.Column(db.String(), unique=False)
    DistinguishedName = db.Column(db.String(), unique=False)
    InfrastructureMaster = db.Column(db.String(), unique=False)
    PasswordPolicies = db.relationship('ADPasswordPolicy', backref='Domain', lazy='dynamic')
    Trusts = db.relationship('ADTrust', backref='Domain', lazy='dynamic')
    DCs = db.relationship('ADDomainController', backref='Domain', lazy='dynamic')
    ComputerList = db.relationship('ADComputer', backref='Domain', lazy='dynamic')
    Users = db.relationship('ADUser', backref='Domain', lazy='dynamic')
    Groups = db.relationship('ADGroup', backref='Domain', lazy='dynamic')

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ADForest(db.Model):
    __tablename__ = "ADForest"
    id = db.Column(db.Integer, primary_key=True)
    DomainNamingMaster = db.Column(db.String(1024), unique=False, nullable=False)
    Name = db.Column(db.String(1024), unique=False)
    RootDomain = db.Column(db.String(1024), unique=False, nullable=False)
    SchemaMaster = db.Column(db.String(1024), unique=False)
    Sites = db.relationship('ADForestSite', backref='Forest', lazy='dynamic')
    GlobalCatalogs = db.relationship('ADForestGlobalCatalog', backref='Forest', lazy='dynamic')
    DCs = db.relationship('ADDomainController', backref='Forest', lazy='dynamic')

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ADTrust(db.Model):
    __tablename__ = "ADTrust"
    id = db.Column(db.Integer, primary_key=True)
    Source = db.Column(db.String(256), unique=False, nullable=False)
    Target = db.Column(db.String(256), unique=False, nullable=False)
    Direction = db.Column(db.String(256), unique=False, nullable=False)
    UplevelOnly = db.Column(db.Boolean(), nullable=True)
    UsesAESKeys = db.Column(db.Boolean(), nullable=True)
    UsesRC4Encryption = db.Column(db.Boolean(), nullable=True)
    TGTDelegation = db.Column(db.Boolean(), nullable=True)
    SIDFilteringForestAware = db.Column(db.Boolean(), nullable=True)
    SIDFilteringQuarantined = db.Column(db.Boolean(), nullable=True)
    SelectiveAuthentication = db.Column(db.Boolean(), nullable=True)
    DisallowTransivity = db.Column(db.Boolean(), nullable=True)
    DistinguishedName = db.Column(db.String(2048), unique=False, nullable=True)
    ForestTransitive = db.Column(db.Boolean(), nullable=True)
    IntraForest = db.Column(db.Boolean(), nullable=True)
    IsTreeParent = db.Column(db.Boolean(), nullable=True)
    IsTreeRoot = db.Column(db.Boolean(), nullable=True)
    Domain_id = db.Column(db.Integer, db.ForeignKey('ADDomain.id'), nullable=False)

    def __repr__(self):
        return self.Target

    def __str__(self):
        return self.Target


class ADForestSite(db.Model):
    __tablename__ = "ADForestSite"
    id = db.Column(db.Integer, primary_key=True)
    Site = db.Column(db.String(1024), unique=False)
    Forest_id = db.Column(db.Integer, db.ForeignKey('ADForest.id'), nullable=False)

    def __repr__(self):
        return self.Site

    def __str__(self):
        return self.Site


class ADPasswordPolicy(db.Model):
    __tablename__ = "ADPasswordPolicy"
    id = db.Column(db.Integer, primary_key=True)
    Type = db.Column(db.String(50), unique=False, nullable=False)
    ComplexityEnabled = db.Column(db.String(10), unique=False)
    DistinguishedName = db.Column(db.String(), unique=False)
    Name = db.Column(db.String(), unique=False)
    LockoutDuration = db.Column(db.String(10), unique=False)
    LockoutObservationWindow = db.Column(db.String(20), unique=False)
    LockoutThreshold = db.Column(db.String(10), unique=False)
    MaxPasswordAge = db.Column(db.String(20), unique=False)
    MinPasswordAge = db.Column(db.String(20), unique=False)
    MinPasswordLength = db.Column(db.String(10), unique=False)
    PasswordHistoryCount = db.Column(db.String(10), unique=False)
    ReversibleEncryptionEnabled = db.Column(db.String(10), unique=False)
    Domain_id = db.Column(db.Integer, db.ForeignKey('ADDomain.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ADForestGlobalCatalog(db.Model):
    __tablename__ = "ADForestGlobalCatalog"
    id = db.Column(db.Integer, primary_key=True)
    GlobalCatalog = db.Column(db.String(1024), unique=False)
    Forest_id = db.Column(db.Integer, db.ForeignKey('ADForest.id'), nullable=False)

    def __repr__(self):
        return self.GlobalCatalog

    def __str__(self):
        return self.GlobalCatalog



class ADDCServerRole(db.Model):
    __tablename__ = "ADDCServerRole"
    id = db.Column(db.Integer, primary_key=True)
    Role = db.Column(db.String(256), unique=False, nullable=False)
    DC_id = db.Column(db.Integer, db.ForeignKey('ADDomainController.id'), nullable=False)

    def __repr__(self):
        return self.Role

    def __str__(self):
        return self.Role


class ADOperationMasterRole(db.Model):
    __tablename__ = "ADOperationMasterRole"
    id = db.Column(db.Integer, primary_key=True)
    Role = db.Column(db.String(256), unique=False, nullable=False)
    DC_id = db.Column(db.Integer, db.ForeignKey('ADDomainController.id'), nullable=False)

    def __repr__(self):
        return self.Role

    def __str__(self):
        return self.Role


class ADDomainController(db.Model):
    __tablename__ = "ADDomainController"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(1024), unique=False, nullable=True)
    Hostname = db.Column(db.String(255), unique=False, nullable=False)
    OperatingSystem = db.Column(db.String(1024), unique=False)
    IPv4Address = db.Column(db.String(16), unique=False, nullable=True)
    IPv6Address = db.Column(db.String(128), unique=False)
    Enabled = db.Column(db.Boolean(), nullable=True)
    Domainname = db.Column(db.String(1024), unique=False)
    Forestname = db.Column(db.String(1024), unique=False)
    IsGlobalCatalog = db.Column(db.Boolean(), nullable=True)
    IsReadOnly = db.Column(db.Boolean(), nullable=True)
    LdapPort = db.Column(db.Integer(), unique=False)
    SslPort = db.Column(db.Integer(), unique=False)
    # ForeignKeys
    Domain_id = db.Column(db.Integer, db.ForeignKey('ADDomain.id'), nullable=False)
    Forest_id = db.Column(db.Integer, db.ForeignKey('ADForest.id'), nullable=False)
    # References
    ServerRoles = db.relationship('ADDCServerRole', backref='DC', lazy='dynamic')
    OperationMasterRoleRoles = db.relationship('ADOperationMasterRole', backref='DC', lazy='dynamic')

    def __repr__(self):
        return self.Hostname

    def __str__(self):
        return self.Hostname


class ADComputer(db.Model):
    __tablename__ = "ADComputer"
    id = db.Column(db.Integer, primary_key=True)
    DistinguishedName = db.Column(db.String(1024), unique=False, nullable=True)
    DNSHostName = db.Column(db.String(1024), unique=False, nullable=True)
    SamAccountName = db.Column(db.String(1024), unique=False, nullable=True)
    Enabled = db.Column(db.Boolean(), nullable=True)
    IPv4Address = db.Column(db.String(1024), unique=False, nullable=True)
    IPv6Address = db.Column(db.String(1024), unique=False)
    SID = db.Column(db.String(1024), unique=False)
    servicePrincipalNames = db.Column(db.String(1024), unique=False)
    TrustedForDelegation = db.Column(db.Boolean(), nullable=True)
    TrustedToAuthForDelegation = db.Column(db.Boolean(), nullable=True)
    PrimaryGroup = db.Column(db.String(1024), unique=False)
    primaryGroupID = db.Column(db.String(10), unique=False)
    pwdLastSet = db.Column(db.String(20), unique=False)
    ProtectedFromAccidentalDeletion = db.Column(db.Boolean(), nullable=True)
    OperatingSystem = db.Column(db.String(1024), unique=False)
    OperatingSystemVersion = db.Column(db.String(100), unique=False)
    Description = db.Column(db.String(2048), unique=False)
    SPNs = db.relationship('ADSPN', backref='Computer', lazy='dynamic')
    Domain_id = db.Column(db.Integer, db.ForeignKey('ADDomain.id'), nullable=False)


    def __repr__(self):
        return self.SamAccountName

    def __str__(self):
        return self.SamAccountName


class ADSPN(db.Model):
    __tablename__ = "ADSPN"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(150), unique=False, nullable=False)
    Computer_id = db.Column(db.Integer, db.ForeignKey('ADComputer.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ADUser(db.Model):
    __tablename__ = "ADUser"
    id = db.Column(db.Integer, primary_key=True)
    SAMAccountName = db.Column(db.String(256), unique=False, nullable=True)
    DistinguishedName = db.Column(db.String(), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    GivenName = db.Column(db.String(), unique=False, nullable=True)
    Surname = db.Column(db.String(), unique=False, nullable=True)
    Name = db.Column(db.String(), unique=False, nullable=True)
    DisplayName = db.Column(db.String(), unique=False, nullable=True)
    SIDHistory = db.Column(db.String(), unique=False, nullable=True)
    Enabled = db.Column(db.Boolean(), nullable=True)
    Description = db.Column(db.String(), unique=False, nullable=True)
    BadLogonCount = db.Column(db.String(10), unique=False, nullable=True)
    BadPwdCount = db.Column(db.String(10), unique=False, nullable=True)
    Created = db.Column(db.String(256), unique=False, nullable=True)
    LastBadPasswordAttempt = db.Column(db.String(20), unique=False, nullable=True)
    lastLogon = db.Column(db.String(20), unique=False, nullable=True)
    logonCount = db.Column(db.String(20), unique=False, nullable=True)
    LockedOut = db.Column(db.Boolean(), nullable=True)
    PasswordExpired = db.Column(db.Boolean(), nullable=True)
    PasswordLastSet = db.Column(db.String(50), unique=False, nullable=True)
    PasswordNeverExpires = db.Column(db.Boolean(), nullable=True)
    PasswordNotRequired = db.Column(db.Boolean(), nullable=True)
    pwdLastSet = db.Column(db.String(50), unique=False, nullable=True)
    Modified = db.Column(db.String(256), unique=False, nullable=True)
    MemberOfStr = db.Column(db.String(), unique=False, nullable=True)
    Memberships = db.relationship('ADUserMembership', backref='User', lazy='dynamic')
    Domain_id = db.Column(db.Integer, db.ForeignKey('ADDomain.id'), nullable=False)

    def __repr__(self):
        return self.SAMAccountName

    def __str__(self):
        return self.SAMAccountName


class ADUserMembership(db.Model):
    __tablename__ = "ADUserMembership"
    id = db.Column(db.Integer, primary_key=True)
    Group = db.Column(db.String(2048), unique=False, nullable=False)
    User_id = db.Column(db.Integer, db.ForeignKey('ADUser.id'), nullable=False)

    def __repr__(self):
        return self.Group

    def __str__(self):
        return self.Group



class ADGroup(db.Model):
    __tablename__ = "ADGroup"
    id = db.Column(db.Integer, primary_key=True)
    CN = db.Column(db.String(1024), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    GroupCategory = db.Column(db.String(256), unique=False, nullable=True)
    GroupScope = db.Column(db.String(50), unique=False, nullable=True)
    SamAccountName = db.Column(db.String(256), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    MemberOfStr = db.Column(db.String(4096), unique=False, nullable=True)
    Members = db.relationship('ADGroupMember', backref='Group', lazy='dynamic')
    Domain_id = db.Column(db.Integer, db.ForeignKey('ADDomain.id'), nullable=False)

    def __repr__(self):
        return self.SamAccountName

    def __str__(self):
        return self.SamAccountName


class ADGroupMember(db.Model):
    __tablename__ = "ADGroupMember"
    id = db.Column(db.Integer, primary_key=True)
    distinguishedName = db.Column(db.String(2048), unique=False, nullable=True)
    Name = db.Column(db.String(356), unique=False, nullable=True)
    SamAccountName = db.Column(db.String(256), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    Group_id = db.Column(db.Integer, db.ForeignKey('ADGroup.id'), nullable=False)

    def __repr__(self):
        return self.SamAccountName

    def __str__(self):
        return self.SamAccountName

