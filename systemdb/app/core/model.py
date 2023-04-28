from .db import db

class ADDomain(db.Model):
    __tablename__ = "ADDomain"
    Id = db.Column(db.Integer, primary_key=True)
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
        return self.name

    def __str__(self):
        return self.name


class ADForest(db.Model):
    __tablename__ = "ADForest"
    Id = db.Column(db.Integer, primary_key=True)
    DomainNamingMaster = db.Column(db.String(1024), unique=False, nullable=False)
    Name = db.Column(db.String(1024), unique=False)
    RootDomain = db.Column(db.String(1024), unique=False, nullable=False)
    SchemaMaster = db.Column(db.String(1024), unique=False)

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name


class ADDCServerRole(db.Model):
    __tablename__ = "ADDCServerRole"
    Id = db.Column(db.Integer, primary_key=True)
    Role = db.Column(db.String(150), unique=False, nullable=False)
    DC_id = db.Column(db.Integer, db.ForeignKey('ADDomainController.id'), nullable=False)

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name


class ADDomainController(db.Model):
    __tablename__ = "ADDomainController"
    Id = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(255), unique=False, nullable=False)
    Hostname = db.Column(db.String(255), unique=False, nullable=False)
    OperatingSystem = db.Column(db.String(1024), unique=False)
    IPv4Address = db.Column(db.String(16), unique=False, nullable=False)
    IPv6Address = db.Column(db.String(128), unique=False)
    Enabled = db.Column(db.String(10), unique=False)
    Domain = db.Column(db.String(1024), unique=False)
    Forest = db.Column(db.String(1024), unique=False)
    IsGlobalCatalog = db.Column(db.String(10), unique=False)
    IsReadOnly = db.Column(db.String(10), unique=False)
    LdapPort = db.Column(db.String(10), unique=False)
    SslPort = db.Column(db.String(10), unique=False)
    ServerRoles = db.relationship('ADDCServerRole', backref='dc', lazy='dynamic')

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name


class ADComputer(db.Model):
    __tablename__ = "ADComputer"
    Id = db.Column(db.Integer, primary_key=True)
    DistinguishedName = db.Column(db.String(1024), unique=False, nullable=False)
    DNSHostName = db.Column(db.String(1024), unique=False, nullable=False)
    SamAccountName = db.Column(db.String(1024), unique=False, nullable=False)
    Enabled = db.Column(db.String(10), unique=False)
    IPv4Address = db.Column(db.String(1024), unique=False, nullable=False)
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

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.name