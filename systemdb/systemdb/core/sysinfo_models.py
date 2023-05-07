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
    HotfixId = db.Column(db.String(150), unique=False, nullable=True)
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
    MacAddress = db.Column(db.String(50), unique=False, nullable=True)
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
    BinaryPermissionsStr = db.Column(db.String(4096), unique=False, nullable=True)
    BinaryPermissions = db.relationship('ServiceACL', backref='nftsshare', lazy='dynamic')
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

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
    AccessRight = db.Column(db.String(150), unique=False, nullable=True)
    Share_id = db.Column(db.Integer, db.ForeignKey('Service.id'), nullable=False)

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


class Share(db.Model):
    __tablename__ = "Share"
    id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(10), unique=False, nullable=True)
    Path = db.Column(db.String(2048), unique=False, nullable=True)
    Description = db.Column(db.String(2048), unique=False, nullable=True)
    NTFSPermission = db.Column(db.String(4096), unique=False, nullable=True)
    SharePermission = db.Column(db.String(4096), unique=False, nullable=True)
    NTFSPermissions = db.relationship('ShareACLNTFS', backref='nftsshare', lazy='dynamic')
    SharePermissions = db.relationship('ShareACL', backref='share', lazy='dynamic')
    Host_id = db.Column(db.Integer, db.ForeignKey('Host.id'), nullable=False)

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
    AccessRight = db.Column(db.String(150), unique=False, nullable=True)
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
    AccessRight = db.Column(db.String(150), unique=False, nullable=True)
    Share_id = db.Column(db.Integer, db.ForeignKey('Share.id'), nullable=False)

    def __repr__(self):
        return self.Name

    def __str__(self):
        return self.Name
