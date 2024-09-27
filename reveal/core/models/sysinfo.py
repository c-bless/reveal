from reveal.core.extentions import db


class Host(db.Model):
    """
    Database model for Hosts imported from results of sysinfo-collector.
    """
    __tablename__ = "Host"
    id = db.Column(db.Integer, primary_key=True)
    Hostname = db.Column(db.String(), unique=False, nullable=False)
    Domain = db.Column(db.String(), unique=False, nullable=True)
    DomainRole = db.Column(db.String(150), unique=False, nullable=True)
    OSVersion = db.Column(db.String(150), unique=False, nullable=True)
    OSBuildNumber = db.Column(db.String(150), unique=False, nullable=True)
    OSName = db.Column(db.String(), unique=False, nullable=True)
    OSInstallDate = db.Column(db.DateTime, unique=False, nullable=True)
    OSProductType = db.Column(db.String(150), unique=False, nullable=True)
    LogonServer = db.Column(db.String(150), unique=False, nullable=True)
    TimeZone = db.Column(db.String(150), unique=False, nullable=True)
    KeyboardLayout = db.Column(db.String(150), unique=False, nullable=True)
    HyperVisorPresent = db.Column(db.Boolean(), nullable=True)
    DeviceGuardSmartStatus = db.Column(db.String(150), unique=False, nullable=True)
    SystemGroup = db.Column(db.String(256), unique=False, nullable=True)
    Location = db.Column(db.String(256), unique=False, nullable=True)
    Label = db.Column(db.String(256), unique=False, nullable=True)
    LastUpdate = db.Column(db.DateTime, unique=False, nullable=True)
    Whoami = db.Column(db.String(256), unique=False, nullable=True)
    WhoamiIsAdmin = db.Column(db.Boolean(), nullable=True)
    #active PS version
    PSVersion = db.Column(db.String(150), unique=False, nullable=True)
    PS2Installed = db.Column(db.Boolean(), unique=False, nullable=True)
    PSScriptBlockLogging = db.Column(db.String(256), unique=False, nullable=True)
    # BIOS
    BiosManufacturer = db.Column(db.String(256), unique=False, nullable=True)
    BiosName = db.Column(db.String(256), unique=False, nullable=True)
    BiosVersion = db.Column(db.String(256), unique=False, nullable=True)
    BiosSerial = db.Column(db.String(256), unique=False, nullable=True)
    # Autologon via Registry
    AutoAdminLogon = db.Column(db.Boolean(), unique=False, nullable=True)
    ForceAutoLogon = db.Column(db.Boolean(), unique=False, nullable=True)
    DefaultPassword = db.Column(db.String(), unique=False, nullable=True)
    DefaultUserName = db.Column(db.String(256), unique=False, nullable=True)
    DefaultDomain = db.Column(db.String(256), unique=False, nullable=True)
    # Firewall Profiles
    FwProfileDomain = db.Column(db.Boolean(), nullable=True)
    FwProfilePrivate = db.Column(db.Boolean(), nullable=True)
    FwProfilePublic = db.Column(db.Boolean(), nullable=True)
    # WSUS
    AcceptTrustedPublisherCerts = db.Column(db.String(5), unique=False, nullable=True)
    DisableWindowsUpdateAccess = db.Column(db.String(5), unique=False, nullable=True)
    ElevateNonAdmins = db.Column(db.String(5), unique=False, nullable=True)
    TargetGroup = db.Column(db.String(), unique=False, nullable=True)
    TargetGroupEnabled = db.Column(db.String(5), unique=False, nullable=True)
    WUServer = db.Column(db.String(), unique=False, nullable=True)
    WUStatusServer = db.Column(db.String(), unique=False, nullable=True)
    # SMB Settings
    SMBv1Enabled = db.Column(db.Boolean(), nullable=True)
    SMBv2Enabled = db.Column(db.Boolean(), nullable=True)
    SMBEncryptData = db.Column(db.Boolean(), nullable=True)
    SMBEnableSecuritySignature = db.Column(db.Boolean(), nullable=True)
    SMBRequireSecuritySignature = db.Column(db.Boolean(), nullable=True)
    # WSH
    WSHTrustPolicy = db.Column(db.String(256), unique=False, nullable=True)
    WSHEnabled = db.Column(db.Boolean(), nullable=True)
    WSHRemote = db.Column(db.Boolean(), nullable=True)
    # references
    PSInstalledVersions = db.relationship("PSInstalledVersions", back_populates='Host', lazy='dynamic')
    Hotfixes = db.relationship('Hotfix', back_populates='Host', lazy='dynamic')
    DefenderStatus = db.relationship('DefenderStatus', back_populates='Host', lazy='dynamic')
    DefenderSettings = db.relationship('DefenderSettings', back_populates='Host', lazy='dynamic')
    Printers = db.relationship('Printer', back_populates='Host', lazy='dynamic')
    NetAdapters = db.relationship('NetAdapter', back_populates='Host', lazy='dynamic')
    NetIPAddresses = db.relationship('NetIPAddress', back_populates='Host', lazy='dynamic')
    Services = db.relationship('Service', back_populates='Host', lazy='dynamic')
    Users = db.relationship('User', back_populates='Host', lazy='dynamic')
    Groups = db.relationship('Group', back_populates='Host', lazy='dynamic')
    Shares = db.relationship('Share', back_populates='Host', lazy='dynamic')
    Products = db.relationship('Product', back_populates='Host', lazy='dynamic')
    ConfigChecks = db.relationship('ConfigCheck', back_populates='Host', lazy='dynamic')
    RegistryChecks = db.relationship('RegistryCheck', back_populates='Host', lazy='dynamic')
    FileExistChecks = db.relationship('FileExistCheck', back_populates='Host', lazy='dynamic')
    PathACLChecks = db.relationship('PathACLCheck', back_populates='Host', lazy='dynamic')
    Routes = db.relationship('Route', back_populates='Host', lazy='dynamic')
    NTPSettings = db.relationship('NTP', back_populates='Host', lazy='dynamic')

    def __repr__(self):
        return self.Hostname

    def __str__(self):
        return self.Hostname

    @staticmethod
    def find_by_hostname(name: str, exact_match=False):
        """
        Finds a list of Host objects.

        :param name: hostname to search for
        :param exact_match: If True the hostname must match exactly. If False the hostname is taken as substring.
        :return: list of Host objects
        """
        if exact_match:
            return Host.query.filter(Host.Hostname == name).all()
        return Host.query.filter(Host.Hostname.ilike('%' + name + '%')).all()


    @staticmethod
    def find_by_domain(name, exact_match=False):
        if exact_match:
            return Host.query.filter(Host.Domain == name).all()
        return Host.query.filter(Host.Domain.ilike('%' + name + '%')).all()

    @staticmethod
    def find_by_os_name(name, exact_match=False):
        if exact_match:
            return Host.query.filter(Host.OSName == name).all()
        return Host.query.filter(Host.OSName.ilike('%' + name + '%')).all()

    @staticmethod
    def find_by_os_buildnumber(buildnumber, exact_match=False):
        if exact_match:
            return Host.query.filter(Host.OSBuildNumber == buildnumber).all()
        return Host.query.filter(Host.OSBuildNumber.ilike('%' + buildnumber + '%')).all()

    @staticmethod
    def find_by_location(name, exact_match=False):
        if exact_match:
            return Host.query.filter(Host.Location == name).all()
        return Host.query.filter(Host.Location.ilike('%' + name + '%')).all()

    @staticmethod
    def find_by_systemgroup(name, exact_match=False):
        if exact_match:
            return Host.query.filter(Host.SystemGroup == name).all()
        return Host.query.filter(Host.SystemGroup.ilike('%' + name + '%')).all()


class Route(db.Model):
    __tablename__ = "Route"
    id = db.Column(db.Integer, primary_key=True)
    AddressFamily = db.Column(db.String(10), unique=False, nullable=True)
    DestinationPrefix = db.Column(db.String(), unique=False, nullable=True)
    InterfaceAlias = db.Column(db.String(), unique=False, nullable=True)
    NextHop = db.Column(db.String(), unique=False, nullable=True)
    RouteMetric = db.Column(db.String(), unique=False, nullable=True)
    IfIndex = db.Column(db.Integer, unique=False, nullable=True)
    InterfaceMetric = db.Column(db.Integer, unique=False, nullable=True)
    IsStatic = db.Column(db.Boolean, unique=False, nullable=True)
    AdminDistance = db.Column(db.Integer, unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Routes")

    def __repr__(self):
        return f"{self.InterfaceAlias} {self.DestinationPrefix}"

    def __str__(self):
        return f"{self.InterfaceAlias} {self.DestinationPrefix}"


class NTP(db.Model):
    __tablename__ = "NTP"
    id = db.Column(db.Integer, primary_key=True)
    Server = db.Column(db.String(), unique=False, nullable=True)
    Type = db.Column(db.String(), unique=False, nullable=True)
    UpdateInterval = db.Column(db.Integer, unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="NTPSettings")

    def __repr__(self):
        return f"{self.Server}"

    def __str__(self):
        return f"{self.Server}"


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

class DefenderStatus(db.Model):
    __tablename__ = "DefenderStatus"
    id = db.Column(db.Integer, primary_key=True)
    AMEngineVersion = db.Column(db.String(), unique=False, nullable=True)
    AMProductVersion = db.Column(db.String(), unique=False, nullable=True)
    AMServiceEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    AMServiceVersion = db.Column(db.String(), unique=False, nullable=True)
    AntispywareEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    AntispywareSignatureLastUpdated = db.Column(db.String(), unique=False, nullable=True)
    AntispywareSignatureVersion = db.Column(db.String(), unique=False, nullable=True)
    AntivirusEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    AntivirusSignatureLastUpdated = db.Column(db.String(), unique=False, nullable=True)
    AntivirusSignatureVersion = db.Column(db.String(), unique=False, nullable=True)
    BehaviorMonitorEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    IoavProtectionEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    IsVirtualMachine = db.Column(db.Boolean(), unique=False, nullable=True)
    NISEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    NISEngineVersion = db.Column(db.String(), unique=False, nullable=True)
    NISSignatureLastUpdated = db.Column(db.String(), unique=False, nullable=True)
    NISSignatureVersion = db.Column(db.String(), unique=False, nullable=True)
    OnAccessProtectionEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    RealTimeProtectionEnabled = db.Column(db.Boolean(), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="DefenderStatus")

    def __repr__(self):
        return "Defender Status"

    def __str__(self):
        return "Defender Status"

class DefenderSettings(db.Model):
    __tablename__ = "DefenderSettings"
    id = db.Column(db.Integer, primary_key=True)
    DisableArchiveScanning = db.Column(db.Boolean, nullable=True)
    DisableAutoExclusions = db.Column(db.Boolean, nullable=True)
    DisableBehaviorMonitoring = db.Column(db.Boolean, nullable=True)
    DisableBlockAtFirstSeen = db.Column(db.Boolean, nullable=True)
    DisableCatchupFullScan = db.Column(db.Boolean, nullable=True)
    DisableCatchupQuickScan = db.Column(db.Boolean, nullable=True)
    DisableEmailScanning = db.Column(db.Boolean, nullable=True)
    DisableIntrusionPreventionSystem = db.Column(db.Boolean, nullable=True)
    DisableIOAVProtection = db.Column(db.Boolean, nullable=True)
    DisableRealtimeMonitoring = db.Column(db.Boolean, nullable=True)
    DisableRemovableDriveScanning = db.Column(db.Boolean, nullable=True)
    DisableRestorePoint = db.Column(db.Boolean, nullable=True)
    DisableScanningMappedNetworkDrivesForFullScan = db.Column(db.Boolean, nullable=True)
    DisableScanningNetworkFiles = db.Column(db.Boolean, nullable=True)
    DisableScriptScanning = db.Column(db.Boolean, nullable=True)
    EnableNetworkProtection = db.Column(db.Boolean, nullable=True)
    ExclusionPath = db.Column(db.String(), unique=False, nullable=True)
    ExclusionProcess = db.Column(db.String(), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="DefenderSettings")

    def __repr__(self):
        return "Defender settings"

    def __str__(self):
        return "Defender settings"


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
    MacAddress = db.Column(db.String(), unique=False, nullable=True)
    Status = db.Column(db.String(), unique=False, nullable=True)
    Name = db.Column(db.String(), unique=False, nullable=True)
    InterfaceDescription = db.Column(db.String(), unique=False, nullable=True)
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
    InterfaceAlias = db.Column(db.String(), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="NetIPAddresses")

    def __repr__(self):
        return self.Interface

    def __str__(self):
        return self.Interface


class Service(db.Model):
    __tablename__ = "Service"
    id = db.Column(db.Integer, primary_key=True)
    Caption = db.Column(db.String(), unique=False, nullable=True)
    Description = db.Column(db.String(), unique=False, nullable=True)
    Name = db.Column(db.String(), unique=False, nullable=True)
    StartMode = db.Column(db.String(20), unique=False, nullable=True)
    PathName = db.Column(db.String(), unique=False, nullable=True)
    Started = db.Column(db.Boolean, unique=False, nullable=True)
    StartName = db.Column(db.String(256), unique=False, nullable=True)
    SystemName = db.Column(db.String(256), unique=False, nullable=True)
    DisplayName = db.Column(db.String(), unique=False, nullable=True)
    AcceptStop = db.Column(db.Boolean, unique=False, nullable=True)
    AcceptPause = db.Column(db.Boolean, unique=False, nullable=True)
    ProcessId = db.Column(db.String(10), unique=False, nullable=True)
    DelayedAutoStart = db.Column(db.Boolean, unique=False, nullable=True)
    BinaryPermissionsStr = db.Column(db.String(), unique=False, nullable=True)
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
    Name = db.Column(db.String(), unique=False, nullable=True)
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
    Disabled = db.Column(db.Boolean(), nullable=True)
    LocalAccount = db.Column(db.Boolean(), nullable=True)
    Name = db.Column(db.String(256), unique=False, nullable=True)
    FullName = db.Column(db.String(1024), unique=False, nullable=True)
    Description = db.Column(db.String(), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    Lockout = db.Column(db.Boolean(), nullable=True)
    PasswordChangeable = db.Column(db.Boolean(), nullable=True)
    PasswordExpires = db.Column(db.Boolean(), nullable=True)
    PasswordRequired = db.Column(db.Boolean(), nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Users")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name

    @staticmethod
    def find_by_name(name: str, exact_match=False):
        if not exact_match:
            return User.query.filter(User.Name.ilike("%" + name + "%")).all()
        return User.query.filter(User.Name == name).all()

    @staticmethod
    def find_by_SID(sid: str, exact_match=False):
        if not exact_match:
            return User.query.filter(User.SID.ilike("%"+ sid + "%")).all()
        return User.query.filter(User.SID == sid).all()

    @staticmethod
    def find_disabled():
        return User.query.filter(User.Disabled == True).all()

    @staticmethod
    def find_enabled():
        return User.query.filter(User.Disabled == False).all()

    @staticmethod
    def find_password_not_required():
        return User.query.filter(User.PasswordRequired == False).all()


class Group(db.Model):
    __tablename__ = "Group"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(512), unique=False, nullable=True)
    Caption = db.Column(db.String(), unique=False, nullable=True)
    Description = db.Column(db.String(), unique=False, nullable=True)
    SID = db.Column(db.String(70), unique=False, nullable=True)
    LocalAccount = db.Column(db.String(10), unique=False, nullable=True)
    Members = db.relationship('GroupMember', backref='Group', lazy='dynamic')
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Groups")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class GroupMember(db.Model):
    __tablename__ = "GroupMember"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(512), unique=False, nullable=True)
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
    Caption = db.Column(db.String(), unique=False, nullable=True)
    InstallDate = db.Column(db.String(150), unique=False, nullable=True)
    Description = db.Column(db.String(), unique=False, nullable=True)
    Vendor = db.Column(db.String(256), unique=False, nullable=True)
    Name = db.Column(db.String(1024), unique=False, nullable=True)
    Version = db.Column(db.String(150), unique=False, nullable=True)
    InstallLocation = db.Column(db.String(), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="Products")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class Share(db.Model):
    __tablename__ = "Share"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(512), unique=False, nullable=True)
    Path = db.Column(db.String(), unique=False, nullable=True)
    Description = db.Column(db.String(), unique=False, nullable=True)
    NTFSPermissions = db.relationship('ShareACLNTFS', back_populates='Share', lazy='dynamic')
    SharePermissions = db.relationship('ShareACL', back_populates='Share', lazy='dynamic')
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
    Share = db.relationship("Share", back_populates="SharePermissions")

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
    Share = db.relationship("Share", back_populates="NTFSPermissions")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name



class ConfigCheck(db.Model):
    __tablename__ = "ConfigCheck"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(512), unique=False, nullable=True)
    Component = db.Column(db.String(256), unique=False, nullable=True)
    Method = db.Column(db.String(256), unique=False, nullable=True)
    Key = db.Column(db.String(), unique=False, nullable=True)
    Value = db.Column(db.String(), unique=False, nullable=True)
    Result = db.Column(db.String(), unique=False, nullable=True)
    Message = db.Column(db.String(), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="ConfigChecks")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name

    @staticmethod
    def find_by_name(name, exact_match=False):
        if exact_match:
            return ConfigCheck.query.filter(ConfigCheck.Name == name).all()
        return ConfigCheck.query.filter(ConfigCheck.Name.ilike('%'+name+'%')).all()

    @staticmethod
    def find_by_component(name, exact_match=False):
        if exact_match:
            return ConfigCheck.query.filter(ConfigCheck.Component == name).all()
        return ConfigCheck.query.filter(ConfigCheck.Component.ilike('%' + name + '%')).all()

    @staticmethod
    def find_by_method(name, exact_match=False):
        if exact_match:
            return ConfigCheck.query.filter(ConfigCheck.Method == name).all()
        return ConfigCheck.query.filter(ConfigCheck.Method.ilike('%' + name + '%')).all()

class RegistryCheck(db.Model):
    __tablename__ = "RegistryCheck"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(512), unique=False, nullable=True)
    Category = db.Column(db.String(256), unique=False, nullable=True)
    Description = db.Column(db.String(), unique=False, nullable=True)
    Tags = db.Column(db.String(), unique=False, nullable=True)
    Path = db.Column(db.String(), unique=False, nullable=True)
    Key = db.Column(db.String(), unique=False, nullable=True)
    Expected = db.Column(db.String(), unique=False, nullable=True)
    KeyExists = db.Column(db.Boolean())
    ValueMatch = db.Column(db.Boolean())
    CurrentValue = db.Column(db.String(), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="RegistryChecks")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name

    @staticmethod
    def find_by_name(name, exact_match=False):
        if exact_match:
            return RegistryCheck.query.filter(RegistryCheck.Name == name).all()
        return RegistryCheck.query.filter(RegistryCheck.Name.ilike('%'+name+'%')).all()

    @staticmethod
    def find_by_category(name, exact_match=False):
        if exact_match:
            return RegistryCheck.query.filter(RegistryCheck.Category == name).all()
        return RegistryCheck.query.filter(RegistryCheck.Category.ilike('%' + name + '%')).all()

    @staticmethod
    def find_by_tag(tag):
        return RegistryCheck.query.filter(RegistryCheck.Tags.ilike('%' + tag + '%')).all()

    @staticmethod
    def find_by_valuematch(match=True):
        return RegistryCheck.query.filter(RegistryCheck.ValueMatch == match).all()


class FileExistCheck(db.Model):
    __tablename__ = "FileExistCheck"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(), unique=False, nullable=True)
    File = db.Column(db.String(), unique=False, nullable=True)
    ExpectedHASH = db.Column(db.String(), unique=False, nullable=True)
    FileExist = db.Column(db.Boolean())
    HashMatch = db.Column(db.Boolean())
    HashChecked = db.Column(db.Boolean())
    CurrentHash = db.Column(db.String(), unique=False, nullable=True)
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="FileExistChecks")

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name


class PathACLCheck(db.Model):
    __tablename__ = "PathACLCheck"
    id = db.Column(db.Integer, primary_key=True)
    Path = db.Column(db.String(), unique=False, nullable=True)
    ACLStr = db.Column(db.String(), unique=False, nullable=True)
    ACLs = db.relationship('PathACL', backref='PathACLCheck', lazy='dynamic')
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)
    Host = db.relationship("Host", back_populates="PathACLChecks")

    def __repr__(self):
        return self.Path

    def __str__(self):
        return self.Path


class PathACL(db.Model):
    __tablename__ = "PathACL"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(), unique=False, nullable=True)
    AccountName = db.Column(db.String(1024), unique=False, nullable=True)
    AccessControlType = db.Column(db.String(150), unique=False, nullable=True)
    AccessRight = db.Column(db.String(1024), unique=False, nullable=True)
    PathACLCheck_id = db.Column(db.Integer, db.ForeignKey('PathACLCheck.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name