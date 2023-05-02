from .db import db

class ADDomain(db.Model):
    __tablename__ = "ADDomain"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(1024), unique=False, nullable=False)
    NetBIOSName = db.Column(db.String(1024), unique=False, nullable=False)
    DNSRoot = db.Column(db.String(1024), unique=False)
    DomainSID = db.Column(db.String(1024), unique=False, nullable=False)
    RIDMaster = db.Column(db.String(1024), unique=False)
    PDCEmulator = db.Column(db.String(1024), unique=False)
    ParentDomain = db.Column(db.String(1024), unique=False)
    Forest = db.Column(db.String(1024), unique=False)
    UsersContainer = db.Column(db.String(1024), unique=False)
    SystemContainer = db.Column(db.String(1024), unique=False)
    ComputerContainer = db.Column(db.String(1024), unique=False)
    DistinguishedName = db.Column(db.String(1024), unique=False)
    InfrastructureMaster = db.Column(db.String(1024), unique=False)

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
    Sites = db.relationship('ADForestSite', backref='dc', lazy='dynamic')
    GlobalCatalogs = db.relationship('ADForestGlobalCatalog', backref='dc', lazy='dynamic')

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
    UplevelOnly = db.Column(db.String(256), unique=False, nullable=True)
    UsesAESKeys = db.Column(db.String(256), unique=False, nullable=True)
    UsesRC4Encryption = db.Column(db.String(256), unique=False, nullable=True)
    TGTDelegation = db.Column(db.String(256), unique=False, nullable=True)
    SIDFilteringForestAware = db.Column(db.String(256), unique=False, nullable=True)
    SIDFilteringQuarantined = db.Column(db.String(256), unique=False, nullable=True)
    SelectiveAuthentication = db.Column(db.String(256), unique=False, nullable=True)
    DisallowTransivity = db.Column(db.String(256), unique=False, nullable=True)
    DistinguishedName = db.Column(db.String(2048), unique=False, nullable=True)
    ForestTransitive = db.Column(db.String(256), unique=False, nullable=True)
    IntraForest = db.Column(db.String(256), unique=False, nullable=True)
    IsTreeParent = db.Column(db.String(256), unique=False, nullable=True)
    IsTreeRoot = db.Column(db.String(256), unique=False, nullable=True)

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
    Role = db.Column(db.String(150), unique=False, nullable=False)
    DC_id = db.Column(db.Integer, db.ForeignKey('ADDomainController.id'), nullable=False)

    def __repr__(self):
        return self.Role

    def __str__(self):
        return self.Role

class ADOperationMasterRole(db.Model):
    __tablename__ = "ADOperationMasterRole"
    id = db.Column(db.Integer, primary_key=True)
    Role = db.Column(db.String(150), unique=False, nullable=False)
    DC_id = db.Column(db.Integer, db.ForeignKey('ADDomainController.id'), nullable=False)

    def __repr__(self):
        return self.Role

    def __str__(self):
        return self.Role


class ADDomainController(db.Model):
    __tablename__ = "ADDomainController"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(255), unique=False, nullable=True)
    Hostname = db.Column(db.String(255), unique=False, nullable=False)
    OperatingSystem = db.Column(db.String(1024), unique=True)
    IPv4Address = db.Column(db.String(16), unique=False, nullable=True)
    IPv6Address = db.Column(db.String(128), unique=True)
    Enabled = db.Column(db.String(10), unique=True)
    Domain = db.Column(db.String(1024), unique=True)
    Forest = db.Column(db.String(1024), unique=True)
    IsGlobalCatalog = db.Column(db.String(10), unique=True)
    IsReadOnly = db.Column(db.String(10), unique=True)
    LdapPort = db.Column(db.String(10), unique=True)
    SslPort = db.Column(db.String(10), unique=True)
    ServerRoles = db.relationship('ADDCServerRole', backref='dc', lazy='dynamic')
    OperationMasterRoleRoles = db.relationship('ADOperationMasterRole', backref='dc', lazy='dynamic')

    def __repr__(self):
        return self.Hostname

    def __str__(self):
        return self.Hostname


class ADComputer(db.Model):
    __tablename__ = "ADComputer"
    id = db.Column(db.Integer, primary_key=True)
    DistinguishedName = db.Column(db.String(1024), unique=False, nullable=True)
    DNSHostName = db.Column(db.String(1024), unique=False, nullable=True)
    SamAccountName = db.Column(db.String(1024), unique=False, nullable=False)
    Enabled = db.Column(db.String(10), unique=False)
    IPv4Address = db.Column(db.String(1024), unique=False, nullable=True)
    IPv6Address = db.Column(db.String(1024), unique=False)
    SID = db.Column(db.String(1024), unique=False)
    servicePrincipalNames = db.Column(db.String(1024), unique=False)
    TrustedForDelegation = db.Column(db.String(10), unique=False)
    TrustedToAuthForDelegation = db.Column(db.String(10), unique=False)
    PrimaryGroup = db.Column(db.String(1024), unique=False)
    primaryGroupID = db.Column(db.String(10), unique=False)
    pwdLastSet = db.Column(db.String(20), unique=False)
    ProtectedFromAccidentalDeletion = db.Column(db.String(10), unique=False)
    OperatingSystem = db.Column(db.String(1024), unique=False)
    OperatingSystemVersion = db.Column(db.String(100), unique=False)
    Description = db.Column(db.String(2048), unique=False)
    SPNs = db.relationship('ADSPN', backref='dc', lazy='dynamic')

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
    SAMAccountName = db.Column(db.String(256), unique=False, nullable=False)
    DistinguishedName = db.Column(db.String(1024), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    GivenName = db.Column(db.String(256), unique=False, nullable=True)
    Surname = db.Column(db.String(256), unique=False, nullable=True)
    Name = db.Column(db.String(256), unique=False, nullable=True)
    SIDHistory = db.Column(db.String(1024), unique=False, nullable=True)
    Enabled = db.Column(db.String(10), unique=False, nullable=True)
    Description = db.Column(db.String(4096), unique=False, nullable=True)
    BadLogonCount = db.Column(db.String(10), unique=False, nullable=True)
    BadPwdCount = db.Column(db.String(10), unique=False, nullable=True)
    Created = db.Column(db.String(256), unique=False, nullable=True)
    LastBadPasswordAttempt = db.Column(db.String(20), unique=False, nullable=True)
    lastLogon = db.Column(db.String(20), unique=False, nullable=True)
    logonCount = db.Column(db.String(20), unique=False, nullable=True)
    LockedOut = db.Column(db.String(10), unique=False, nullable=True)
    PasswordExpired = db.Column(db.String(10), unique=False, nullable=True)
    PasswordLastSet = db.Column(db.String(50), unique=False, nullable=True)
    PasswordNeverExpires = db.Column(db.String(10), unique=False, nullable=True)
    PasswordNotRequired = db.Column(db.String(10), unique=False, nullable=True)
    pwdLastSet = db.Column(db.String(50), unique=False, nullable=True)
    Modified = db.Column(db.String(256), unique=False, nullable=True)
    MemberOfStr = db.Column(db.String(4096), unique=False, nullable=True)
    Members = db.relationship('ADUserMemberGroup', backref='dc', lazy='dynamic')

    def __repr__(self):
        return self.SAMAccountName

    def __str__(self):
        return self.SAMAccountName


class ADUserMemberGroup(db.Model):
    __tablename__ = "ADUserMemberGroup"
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
    Members = db.relationship('ADGroupMember', backref='dc', lazy='dynamic')

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



class Host(db.Model):
    __tablename__ = "Host"
    id = db.Column(db.Integer, primary_key=True)
    Hostname = db.Column(db.String(150), unique=False, nullable=False)
    Domain = db.Column(db.String(150), unique=False, nullable=True)
    DomainRole = db.Column(db.String(150), unique=False, nullable=True)
    OSVersion = db.Column(db.String(150), unique=False, nullable=True)
    OSBuildNumber = db.Column(db.String(150), unique=False, nullable=True)
    OSName = db.Column(db.String(150), unique=False, nullable=True)
    OSInstallDate = db.Column(db.String(150), unique=False, nullable=True)
    OSProductType = db.Column(db.String(150), unique=False, nullable=True)
    LogonServer = db.Column(db.String(150), unique=False, nullable=True)
    TimeZone = db.Column(db.String(150), unique=False, nullable=True)
    KeyboardLayout = db.Column(db.String(150), unique=False, nullable=True)
    HyperVisorPresent = db.Column(db.String(150), unique=False, nullable=True)
    DeviceGuardSmartStatus = db.Column(db.String(150), unique=False, nullable=True)
    PSVersion = db.Column(db.String(150), unique=False, nullable=True)
    Hotfixes = db.relationship('Hotfix', backref='dc', lazy='dynamic')
    NetAdapters = db.relationship('NetAdapter', backref='dc', lazy='dynamic')
    NetIPAddresses = db.relationship('NetIPAddress', backref='dc', lazy='dynamic')
    Services = db.relationship('Service', backref='dc', lazy='dynamic')
    Users = db.relationship('User', backref='dc', lazy='dynamic')
    Groups = db.relationship('Group', backref='dc', lazy='dynamic')
    Shares = db.relationship('Share', backref='dc', lazy='dynamic')
    Products = db.relationship('Product', backref='dc', lazy='dynamic')
    # Autologon via Registry
    AutoAdminLogon = db.Column(db.String(4), unique=False, nullable=True)
    ForceAutoLogon = db.Column(db.String(4), unique=False, nullable=True)
    DefaultPassword = db.Column(db.String(256), unique=False, nullable=True)
    DefaultUserName = db.Column(db.String(256), unique=False, nullable=True)
    DefaultDomain = db.Column(db.String(256), unique=False, nullable=True)

    def __repr__(self):
        return self.Hostname

    def __str__(self):
        return self.Hostname

class Hotfix(db.Model):
    __tablename__ = "Hotfix"
    id = db.Column(db.Integer, primary_key=True)
    HotfixId = db.Column(db.String(150), unique=False, nullable=False)
    InstalledOn = db.Column(db.String(150), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.HotfixId

    def __str__(self):
        return self.HotfixId



class NetAdapter(db.Model):
    __tablename__ = "NetAdapter"
    id = db.Column(db.Integer, primary_key=True)
    MacAddress = db.Column(db.String(50), unique=False, nullable=False)
    Status = db.Column(db.String(10), unique=False, nullable=True)
    Name = db.Column(db.String(256), unique=False, nullable=True)
    InterfaceDescription = db.Column(db.String(2048), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name

class NetIPAddress(db.Model):
    __tablename__ = "NetIPAddress"
    id = db.Column(db.Integer, primary_key=True)
    AddressFamily = db.Column(db.String(10), unique=False, nullable=False)
    Prefix = db.Column(db.String(4), unique=False, nullable=True)
    IP = db.Column(db.String(150), unique=False, nullable=True)
    Type = db.Column(db.String(256), unique=False, nullable=True)
    InterfaceAlias = db.Column(db.String(256), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Interface

    def __str__(self):
        return self.Interface

class Service(db.Model):
    __tablename__ = "Service"
    id = db.Column(db.Integer, primary_key=True)
    Caption = db.Column(db.String(2048), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    Name = db.Column(db.String(1024), unique=False, nullable=True)
    StartMode = db.Column(db.String(20), unique=False, nullable=True)
    PathName = db.Column(db.String(2048), unique=False, nullable=True)
    Started = db.Column(db.String(10), unique=False, nullable=True)
    StartName = db.Column(db.String(256), unique=False, nullable=True)
    SystemName = db.Column(db.String(256), unique=False, nullable=True)
    DisplayName = db.Column(db.String(1024), unique=False, nullable=True)
    Running = db.Column(db.String(256), unique=False, nullable=True)
    AcceptStop = db.Column(db.String(10), unique=False, nullable=True)
    AcceptPause = db.Column(db.String(10), unique=False, nullable=True)
    ProcessId = db.Column(db.String(10), unique=False, nullable=True)
    DelayedAutoStart = db.Column(db.String(10), unique=False, nullable=True)
    BinaryPermissions = db.Column(db.String(4096), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class User(db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    AccountType = db.Column(db.String(10), unique=False, nullable=True)
    Domain = db.Column(db.String(1024), unique=False, nullable=True)
    Disabled = db.Column(db.String(10), unique=False, nullable=True)
    LocalAccount = db.Column(db.String(10), unique=False, nullable=True)
    Name = db.Column(db.String(256), unique=False, nullable=True)
    FullName = db.Column(db.String(1024), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    Lockout = db.Column(db.String(10), unique=False, nullable=True)
    PasswordChanged = db.Column(db.String(10), unique=False, nullable=True)
    PasswordRequired = db.Column(db.String(10), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name

class Group(db.Model):
    __tablename__ = "Group"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(10), unique=False, nullable=True)
    Caption = db.Column(db.String(2048), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    LocalAccount = db.Column(db.String(10), unique=False, nullable=True)
    Members = db.relationship('GroupMember', backref='dc', lazy='dynamic')
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class GroupMember(db.Model):
    __tablename__ = "GroupMember"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(10), unique=False, nullable=True)
    Caption = db.Column(db.String(2048), unique=False, nullable=True)
    Domain = db.Column(db.String(256), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    AccountType = db.Column(db.String(50), unique=False, nullable=True)
    Group_id = db.Column(db.Integer, db.ForeignKey('Group.id'), nullable=False)

    def __repr__(self):
        return self.Caption

    def __str__(self):
        return self.Caption

class Share(db.Model):
    __tablename__ = "Share"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(10), unique=False, nullable=True)
    Path = db.Column(db.String(2048), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    NTFSPermission = db.Column(db.String(4096), unique=False, nullable=True)
    SharePermission = db.Column(db.String(4096), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class Product(db.Model):
    __tablename__ = "Product"
    id = db.Column(db.Integer, primary_key=True)
    Caption = db.Column(db.String(150), unique=False, nullable=True)
    InstallDate = db.Column(db.String(150), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    Vendor = db.Column(db.String(256), unique=False, nullable=True)
    Name = db.Column(db.String(1024), unique=False, nullable=True)
    Version = db.Column(db.String(150), unique=False, nullable=True)
    InstallLocation = db.Column(db.String(2048), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


