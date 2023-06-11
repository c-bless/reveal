from .db import db


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
    SystemGroup = db.Column(db.String(256), unique=False, nullable=True)
    Location = db.Column(db.String(256), unique=False, nullable=True)
    LastUpdate = db.Column(db.DateTime, unique=False, nullable=True)
    #active PS version
    PSVersion = db.Column(db.String(150), unique=False, nullable=True)
    PS2Installed = db.Column(db.String(10), unique=False, nullable=True)
    PSScriptBlockLogging = db.Column(db.String(256), unique=False, nullable=True)
    # BIOS
    BiosManufacturer = db.Column(db.String(256), unique=False, nullable=True)
    BiosName = db.Column(db.String(256), unique=False, nullable=True)
    BiosVersion = db.Column(db.String(256), unique=False, nullable=True)
    BiosSerial = db.Column(db.String(256), unique=False, nullable=True)
    # Autologon via Registry
    AutoAdminLogon = db.Column(db.String(4), unique=False, nullable=True)
    ForceAutoLogon = db.Column(db.String(4), unique=False, nullable=True)
    DefaultPassword = db.Column(db.String(256), unique=False, nullable=True)
    DefaultUserName = db.Column(db.String(256), unique=False, nullable=True)
    DefaultDomain = db.Column(db.String(256), unique=False, nullable=True)
    # Firewall Profiles
    FwProfileDomain = db.Column(db.String(5),  unique=False, nullable=True)
    FwProfilePrivate = db.Column(db.String(5),  unique=False, nullable=True)
    FwProfilePublic = db.Column(db.String(5),  unique=False, nullable=True)
    # WSUS
    AcceptTrustedPublisherCerts = db.Column(db.String(5), unique=False, nullable=True)
    DisableWindowsUpdateAccess = db.Column(db.String(5), unique=False, nullable=True)
    ElevateNonAdmins = db.Column(db.String(5), unique=False, nullable=True)
    TargetGroup = db.Column(db.String(256), unique=False, nullable=True)
    TargetGroupEnabled = db.Column(db.String(5), unique=False, nullable=True)
    WUServer = db.Column(db.String(1024), unique=False, nullable=True)
    WUStatusServer = db.Column(db.String(1024), unique=False, nullable=True)
    # SMB Settings
    SMBv1Enabled = db.Column(db.String(5), unique=False, nullable=True)
    SMBv2Enabled = db.Column(db.String(5), unique=False, nullable=True)
    SMBEncryptData = db.Column(db.String(5), unique=False, nullable=True)
    SMBEnableSecuritySignature = db.Column(db.String(5), unique=False, nullable=True)
    SMBRequireSecuritySignature = db.Column(db.String(5), unique=False, nullable=True)
    # WSH
    WSHTrustPolicy = db.Column(db.String(256), unique=False, nullable=True)
    WSHEnabled = db.Column(db.String(10), unique=False, nullable=True)
    WSHRemote = db.Column(db.String(10), unique=False, nullable=True)
    # references
    PSInstalledVersions = db.relationship("PSInstalledVersions", back_populates='Host', lazy='dynamic')
    Hotfixes = db.relationship('Hotfix', back_populates='Host', lazy='dynamic')
    DefenderSettings = db.relationship('DefenderSettings', back_populates='Host', lazy='dynamic')
    Printers = db.relationship('Printer', back_populates='Host', lazy='dynamic')
    NetAdapters = db.relationship('NetAdapter', back_populates='Host', lazy='dynamic')
    NetIPAddresses = db.relationship('NetIPAddress', back_populates='Host', lazy='dynamic')
    Services = db.relationship('Service', back_populates='Host', lazy='dynamic')
    Users = db.relationship('User', back_populates='Host', lazy='dynamic')
    Groups = db.relationship('Group', back_populates='Host', lazy='dynamic')
    Shares = db.relationship('Share', back_populates='Host', lazy='dynamic')
    Products = db.relationship('Product', back_populates='Host', lazy='dynamic')

    def __repr__(self):
        return self.Hostname

    def __str__(self):
        return self.Hostname


class PSInstalledVersions(db.Model):
    __tablename__ = "PSInstalledVersions"
    id = db.Column(db.Integer, primary_key=True)
    PSVersion = db.Column(db.String(150), unique=False, nullable=True)
    PSCompatibleVersion = db.Column(db.String(256), unique=False, nullable=True)
    PSPath = db.Column(db.String(2048), unique=False, nullable=True)
    RuntimeVersion = db.Column(db.String(256), unique=False, nullable=True)
    ConsoleHostModuleName = db.Column(db.String(256), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="PSInstalledVersions")

    def __repr__(self):
        return self.PSVersion

    def __str__(self):
        return self.PSVersion


class Hotfix(db.Model):
    __tablename__ = "Hotfix"
    id = db.Column(db.Integer, primary_key=True)
    HotfixId = db.Column(db.String(150), unique=False, nullable=True)
    InstalledOn = db.Column(db.DateTime, unique=False, nullable=True)
    InstalledOnStr = db.Column(db.String(150), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Hotfixes")

    def __repr__(self):
        return self.HotfixId

    def __str__(self):
        return self.HotfixId


class DefenderSettings(db.Model):
    __tablename__ = "DefenderSettings"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(256), unique=False, nullable=True)
    Value = db.Column(db.String(256), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="DefenderSettings")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class Printer(db.Model):
    __tablename__ = "Printer"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(256), unique=False, nullable=True)
    Type = db.Column(db.String(100), unique=False, nullable=True)
    DriverName = db.Column(db.String(256), unique=False, nullable=True)
    ShareName = db.Column(db.String(256), unique=False, nullable=True)
    PortName = db.Column(db.String(256), unique=False, nullable=True)
    Shared = db.Column(db.String(10), unique=False, nullable=True)
    Published = db.Column(db.String(10), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Printers")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class NetAdapter(db.Model):
    __tablename__ = "NetAdapter"
    id = db.Column(db.Integer, primary_key=True)
    MacAddress = db.Column(db.String(50), unique=False, nullable=True)
    Status = db.Column(db.String(10), unique=False, nullable=True)
    Name = db.Column(db.String(256), unique=False, nullable=True)
    InterfaceDescription = db.Column(db.String(2048), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="NetAdapters")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class NetIPAddress(db.Model):
    __tablename__ = "NetIPAddress"
    id = db.Column(db.Integer, primary_key=True)
    AddressFamily = db.Column(db.String(10), unique=False, nullable=True)
    Prefix = db.Column(db.String(4), unique=False, nullable=True)
    IP = db.Column(db.String(150), unique=False, nullable=True)
    Type = db.Column(db.String(256), unique=False, nullable=True)
    InterfaceAlias = db.Column(db.String(256), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="NetIPAddresses")

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
    BinaryPermissionsStr = db.Column(db.String(4096), unique=False, nullable=True)
    BinaryPermissions = db.relationship('ServiceACL', backref='Service', lazy='dynamic')
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Services")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ServiceACL(db.Model):
    __tablename__ = "ServiceACL"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(150), unique=False, nullable=True)
    AccountName = db.Column(db.String(1024), unique=False, nullable=True)
    AccessControlType = db.Column(db.String(150), unique=False, nullable=True)
    AccessRight = db.Column(db.String(1024), unique=False, nullable=True)
    Service_id = db.Column(db.Integer, db.ForeignKey('Service.id'), nullable=False)

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
    Host = db.relationship("Host", back_populates="Users")

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
    Host = db.relationship("Host", back_populates="Groups")

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
    Host = db.relationship("Host", back_populates="Products")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class Share(db.Model):
    __tablename__ = "Share"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(10), unique=False, nullable=True)
    Path = db.Column(db.String(2048), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    NTFSPermission = db.Column(db.String(4096), unique=False, nullable=True)
    SharePermission = db.Column(db.String(4096), unique=False, nullable=True)
    NTFSPermissions = db.relationship('ShareACLNTFS', backref='share', lazy='dynamic')
    SharePermissions = db.relationship('ShareACL', backref='share', lazy='dynamic')
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Shares")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ShareACL(db.Model):
    __tablename__ = "ShareACL"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(150), unique=False, nullable=True)
    ScopeName = db.Column(db.String(150), unique=False, nullable=True)
    AccountName = db.Column(db.String(1024), unique=False, nullable=True)
    AccessControlType = db.Column(db.String(150), unique=False, nullable=True)
    AccessRight = db.Column(db.String(1024), unique=False, nullable=True)
    Share_id = db.Column(db.Integer, db.ForeignKey('Share.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ShareACLNTFS(db.Model):
    __tablename__ = "ShareACLNTFS"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(150), unique=False, nullable=True)
    AccountName = db.Column(db.String(1024), unique=False, nullable=True)
    AccessControlType = db.Column(db.String(150), unique=False, nullable=True)
    AccessRight = db.Column(db.String(1024), unique=False, nullable=True)
    Share_id = db.Column(db.Integer, db.ForeignKey('Share.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class ConfigCheck(db.Model):
    __tablename__ = "ConfigCheck"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(150), unique=False, nullable=True)
    Component = db.Column(db.String(256), unique=False, nullable=True)
    Method = db.Column(db.String(256), unique=False, nullable=True)
    Key = db.Column(db.String(256), unique=False, nullable=True)
    Value = db.Column(db.String(256), unique=False, nullable=True)
    Result = db.Column(db.String(256), unique=False, nullable=True)
    Message = db.Column(db.String(4096), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name

