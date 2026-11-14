"""
Importer for the output of the SystemInfoCollector (sysinfo-collector.ps1) version >= 0.7.

The collector can export the collected data as XML, as JSON or both. Both formats contain the same information.
The XML document is converted into the same dictionary structure as the JSON file (see xml2sysinfo), so a single
function (sysinfo2db) writes the data of both formats to the database.

Files of older collector versions (< 0.7) are imported with the legacy importer in reveal.core.importer.hosts.

Structure of the dictionary (= JSON file):

    {
        "Version": "0.6",
        "HostInfo": {...},              "BiosInfo": {...},
        "Hotfixes": [...],              "InstalledProducts": [...],
        "NetAdapter": [...],            "NetIPs": [...],                "Routes": [...],
        "Users": [...],                 "Groups": [{..., "Members": [...]}],
        "FileChecksResults": [...],     "RegistryCheckResults": [...],  "ConfigCheckResults": [...],
        "FirewallInfo": [...],          "Shares": [{..., "NTFSPermissions": [...], "SharePermissions": [...]}],
        "WsusSettings": {...},          "Winlogon": {...},              "PSVersions": [...],
        "WSHSettings": {...},           "NTPSettings": {...},           "PSLogging": {...},
        "SMBConfig": {...},             "DefenderInfo": {"MpComputerStatus": {...}, "MpPreference": {...}},
        "Printers": [...],              "Services": [{..., "BinaryPermissions": [...]}],
        "AclPathChecks": [{"Path": ..., "ACLs": [...]}]
    }
"""
import base64
import json

from flask import current_app
from sqlalchemy.exc import SQLAlchemyError

from reveal.core.extentions import db
from reveal.core.models.sysinfo import ConfigCheck
from reveal.core.models.sysinfo import DefenderSettings
from reveal.core.models.sysinfo import DefenderStatus
from reveal.core.models.sysinfo import FileExistCheck
from reveal.core.models.sysinfo import Group
from reveal.core.models.sysinfo import GroupMember
from reveal.core.models.sysinfo import Host
from reveal.core.models.sysinfo import Hotfix
from reveal.core.models.sysinfo import NetAdapter
from reveal.core.models.sysinfo import NetIPAddress
from reveal.core.models.sysinfo import NTP
from reveal.core.models.sysinfo import PathACL
from reveal.core.models.sysinfo import PathACLCheck
from reveal.core.models.sysinfo import Printer
from reveal.core.models.sysinfo import Product
from reveal.core.models.sysinfo import PSInstalledVersions
from reveal.core.models.sysinfo import RegistryCheck
from reveal.core.models.sysinfo import Route
from reveal.core.models.sysinfo import Service
from reveal.core.models.sysinfo import ServiceACL
from reveal.core.models.sysinfo import Share
from reveal.core.models.sysinfo import ShareACL
from reveal.core.models.sysinfo import ShareACLNTFS
from reveal.core.models.sysinfo import User
from reveal.core.importer.converter import str2bool_or_none
from reveal.core.importer.converter import network_protection_or_none
from reveal.core.importer.converter import str2datetime_or_none
from reveal.core.importer.converter import collection_date_or_none
from reveal.core.util import decrypt_ps
from reveal.core.util import encrypt

# first collector version that is imported with this importer. Older files are imported with the legacy importer.
MIN_VERSION = (0, 6)


###################################################################################################################
# Format detection
###################################################################################################################
def parse_version(version) -> tuple:
    """
    Converts a version string (e.g. "0.7" or "0.6.1") into a tuple of integers. Invalid versions result in (0,).
    """
    try:
        return tuple(int(p) for p in str(version).strip().split("."))
    except (ValueError, AttributeError):
        return (0,)


def is_sysinfo_xml(root) -> bool:
    """
    Returns True if the XML root element has been created by a SystemInfoCollector that is handled by this importer.
    """
    return root.tag == "SystemInfoCollector" and parse_version(root.get("version")) >= MIN_VERSION


def is_sysinfo_json(data) -> bool:
    """
    Returns True if the loaded JSON data has been created by the SystemInfoCollector.
    """
    if isinstance(data, list):
        return len(data) > 0 and all(is_sysinfo_json(d) for d in data)
    return isinstance(data, dict) and "HostInfo" in data


###################################################################################################################
# Value converters (values in JSON files can be strings, booleans, numbers or null)
###################################################################################################################
def _str(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    value = str(value)
    return value if value != "" else None


def _bool(value):
    if isinstance(value, bool):
        return value
    return str2bool_or_none(_str(value))


def _int(value):
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(_str(value))
    except (TypeError, ValueError):
        return None


def _date(value):
    return str2datetime_or_none(_str(value))


def _list(value) -> list:
    """ PowerShell serializes empty lists as null and (in some versions) lists with one entry as object. """
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _obj(value) -> dict:
    return value if isinstance(value, dict) else {}


###################################################################################################################
# XML -> dictionary (same structure as the JSON file)
###################################################################################################################
def _children(elem, tag=None):
    """ Child elements (comments and processing instructions are skipped). Works with lxml and ElementTree. """
    for c in elem:
        if isinstance(c.tag, str) and (tag is None or c.tag == tag):
            yield c


def _text(elem):
    return elem.text if elem.text else None


def _record(elem) -> dict:
    """ Attributes and leaf child elements (elements without children) of an element as dictionary. """
    record = dict(elem.attrib)
    for c in _children(elem):
        if len(list(_children(c))) == 0:
            record[c.tag] = _text(c)
    return record


def _attrib_list(elem, container, item) -> list:
    """ Attributes of the elements <container><item .../></container> below elem. """
    result = []
    for cont in _children(elem, container):
        for i in _children(cont, item):
            result.append(dict(i.attrib))
    return result


def _parse_winlogon(elem) -> dict:
    winlogon = _record(elem)
    for pw in _children(elem, "DefaultPassword"):
        winlogon["DefaultPassword"] = _text(pw)
        # attribute names are compared case insensitive (older collector versions used "Base64" and "Encrypted")
        attrs = {k.lower(): v for k, v in pw.attrib.items()}
        winlogon["DefaultPasswordBase64"] = attrs.get("base64")
        winlogon["DefaultPasswordEncrypted"] = attrs.get("encrypted")
    if "DefaultDomainName" not in winlogon and "DefaultDomain" in winlogon:
        winlogon["DefaultDomainName"] = winlogon.get("DefaultDomain")
    return winlogon


def _parse_defender(elem, data):
    defender = data.setdefault("DefenderInfo", {})
    if elem.tag == "DefenderStatus":
        defender["MpComputerStatus"] = _record(elem)
        return
    nested = [c for c in _children(elem) if c.tag in ("DefenderStatus", "Defender")]
    if nested:
        # older collector versions wrapped DefenderStatus and Defender in an additional Defender element
        for c in nested:
            _parse_defender(c, data)
    else:
        defender["MpPreference"] = _record(elem)


def _parse_host(host_elem) -> dict:
    data = {"HostInfo": {}}
    hotfixes_last_update = None

    for e in _children(host_elem):
        tag = e.tag
        if tag == "BIOS":
            bios = dict(e.attrib)
            if not bios.get("SerialNumber"):
                bios["SerialNumber"] = bios.get("Serial")
            data["BiosInfo"] = bios
        elif tag == "Hotfixes":
            hotfixes_last_update = e.get("LastUpdate")
            data["Hotfixes"] = [dict(h.attrib) for h in _children(e, "Hotfix")]
        elif tag == "Products":
            data["InstalledProducts"] = [_record(p) for p in _children(e, "Product")]
        elif tag == "Netadapters":
            data["NetAdapter"] = [dict(n.attrib) for n in _children(e, "Netadapter")]
        elif tag == "NetIPAddresses":
            data["NetIPs"] = [dict(n.attrib) for n in _children(e, "NetIPAddress")]
        elif tag == "Routes":
            routes = []
            for r in _children(e, "Route"):
                route = _record(r)
                if "IfIndex" not in route and "ifIndex" in route:
                    route["IfIndex"] = route.get("ifIndex")
                routes.append(route)
            data["Routes"] = routes
        elif tag == "Users":
            data["Users"] = [_record(u) for u in _children(e, "User")]
        elif tag == "Groups":
            groups = []
            for g in _children(e, "Group"):
                group = _record(g)
                group["Members"] = [_record(m) for ms in _children(g, "Members") for m in _children(ms, "Member")]
                groups.append(group)
            data["Groups"] = groups
        elif tag == "FileExistChecks":
            data["FileChecksResults"] = [_record(c) for c in _children(e, "FileExistCheck")]
        elif tag == "NetFirewallProfiles":
            data["FirewallInfo"] = [dict(f.attrib) for f in _children(e, "FwProfile")]
        elif tag == "AdditionalRegistryChecks":
            data["RegistryCheckResults"] = [_record(c) for c in _children(e, "RegistryCheck")]
        elif tag == "Shares":
            shares = []
            for s in _children(e, "Share"):
                share = _record(s)
                share["NTFSPermissions"] = _attrib_list(s, "NTFSPermissions", "Permission")
                share["SharePermissions"] = _attrib_list(s, "SharePermissions", "Permission")
                shares.append(share)
            data["Shares"] = shares
        elif tag == "WSUS":
            data["WsusSettings"] = _record(e)
        elif tag == "Winlogon":
            data["Winlogon"] = _parse_winlogon(e)
        elif tag == "PSVersions":
            versions = []
            for p in _children(e, "PSVersion"):
                v = dict(p.attrib)
                v["PowerShellVersion"] = v.get("PSVersion") or v.get("Version")
                versions.append(v)
            data["PSVersions"] = versions
        elif tag == "WSH":
            data["WSHSettings"] = _record(e)
        elif tag == "NTP":
            data["NTPSettings"] = _record(e)
        elif tag == "PSScriptBlockLogging":
            data["PSLogging"] = {"PSScriptBlockLogging": _text(e)}
        elif tag == "SMBSettings":
            data["SMBConfig"] = _record(e)
        elif tag in ("DefenderStatus", "Defender"):
            _parse_defender(e, data)
        elif tag == "Printers":
            data["Printers"] = [_record(p) for p in _children(e, "Printer")]
        elif tag == "Services":
            services = []
            for s in _children(e, "Service"):
                service = _record(s)
                service["BinaryPermissions"] = _attrib_list(s, "BinaryPermissions", "Permission")
                services.append(service)
            data["Services"] = services
        elif tag == "PathACLChecks":
            checks = []
            for c in _children(e, "PathACL"):
                check = _record(c)
                check["ACLs"] = _attrib_list(c, "ACLs", "ACL")
                checks.append(check)
            data["AclPathChecks"] = checks
        elif tag == "ConfigChecks":
            data["ConfigCheckResults"] = [_record(c) for c in _children(e, "ConfigCheck")]
        elif len(list(_children(e))) == 0:
            # general host information (Hostname, Domain, OSVersion, ...)
            data["HostInfo"][tag] = _text(e)

    last_update = data["HostInfo"].get("LastUpdate")
    if (not last_update or last_update == "N/A") and hotfixes_last_update:
        data["HostInfo"]["LastUpdate"] = hotfixes_last_update
    return data


def xml2sysinfo(root) -> list:
    """
    Converts the XML document of the SystemInfoCollector into a list of dictionaries (one per Host element) with the
    same structure as the JSON file.
    """
    result = []
    for host_elem in _children(root, "Host"):
        data = _parse_host(host_elem)
        data["Version"] = root.get("version")
        result.append(data)
    return result


###################################################################################################################
# dictionary -> database
###################################################################################################################
def _decode_default_password(winlogon: dict):
    """
    Decrypts / decodes the DefaultPassword from the collector and re-encrypts it with the AES_KEY of REVEAL.
    """
    password = _str(winlogon.get("DefaultPassword"))
    if not password:
        return None
    try:
        if _bool(winlogon.get("DefaultPasswordEncrypted")):
            # AES encrypted by the collector script (IV + cipher text, base64 encoded)
            plaintext = decrypt_ps(password, key=current_app.config.get("IMPORT_KEY")).decode("utf-8")
        elif _bool(winlogon.get("DefaultPasswordBase64")):
            plaintext = base64.b64decode(password.encode("utf-8")).decode("utf-8")
        else:
            plaintext = password
        return encrypt(plain_text=plaintext, key=current_app.config.get("AES_KEY"))
    except Exception as e:
        print("Error while decrypting DefaultPassword. Error: {0}".format(str(e)))
        return None


def _new_host(data: dict) -> Host:
    """ Creates the host object with all attributes that are stored directly in the Host table. """
    info = _obj(data.get("HostInfo"))
    host = Host()
    host.Hostname = _str(info.get("Hostname"))
    host.CollectionDate = collection_date_or_none(_str(info.get("CollectionDate")))
    host.Domain = _str(info.get("Domain"))
    host.DomainRole = _str(info.get("DomainRole"))
    host.OSVersion = _str(info.get("OSVersion"))
    host.OSBuildNumber = _str(info.get("OSBuildNumber"))
    host.OSName = _str(info.get("OSName"))
    host.OSInstallDate = _date(info.get("OSInstallDate"))
    host.OSProductType = _str(info.get("OSProductType"))
    host.LogonServer = _str(info.get("LogonServer"))
    host.TimeZone = _str(info.get("TimeZone"))
    host.KeyboardLayout = _str(info.get("KeyboardLayout"))
    host.HyperVisorPresent = _bool(info.get("HyperVisorPresent"))
    host.DeviceGuardSmartStatus = _str(info.get("DeviceGuardSmartStatus"))
    host.PSVersion = _str(info.get("PSVersion"))
    host.PS2Installed = _bool(info.get("PSVersion2Installed"))
    host.SystemGroup = _str(info.get("SystemGroup"))
    host.Location = _str(info.get("Location"))
    host.Label = _str(info.get("Label"))
    host.Whoami = _str(info.get("Whoami"))
    host.WhoamiIsAdmin = _bool(info.get("WhoamiIsAdmin"))
    host.LastUpdate = _date(info.get("LastUpdate"))

    bios = _obj(data.get("BiosInfo"))
    host.BiosManufacturer = _str(bios.get("Manufacturer"))
    host.BiosName = _str(bios.get("Name"))
    host.BiosVersion = _str(bios.get("Version"))
    host.BiosSerial = _str(bios.get("SerialNumber") or bios.get("Serial"))

    host.PSScriptBlockLogging = _str(_obj(data.get("PSLogging")).get("PSScriptBlockLogging"))

    for fw in _list(data.get("FirewallInfo")):
        name = _str(fw.get("Name"))
        enabled = _bool(fw.get("Enabled"))
        if name == "Domain":
            host.FwProfileDomain = enabled
        elif name == "Private":
            host.FwProfilePrivate = enabled
        elif name == "Public":
            host.FwProfilePublic = enabled

    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd939844(v=ws.10)
    wsus = _obj(data.get("WsusSettings"))
    host.AcceptTrustedPublisherCerts = _str(wsus.get("AcceptTrustedPublisherCerts"))
    host.DisableWindowsUpdateAccess = _str(wsus.get("DisableWindowsUpdateAccess"))
    host.ElevateNonAdmins = _str(wsus.get("ElevateNonAdmins"))
    host.TargetGroup = _str(wsus.get("TargetGroup"))
    host.TargetGroupEnabled = _str(wsus.get("TargetGroupEnabled"))
    host.WUServer = _str(wsus.get("WUServer"))
    host.WUStatusServer = _str(wsus.get("WUStatusServer"))

    smb = _obj(data.get("SMBConfig"))
    host.SMBv1Enabled = _bool(smb.get("SMB1Enabled"))
    host.SMBv2Enabled = _bool(smb.get("SMB2Enabled"))
    host.SMBEncryptData = _bool(smb.get("EncryptData"))
    host.SMBEnableSecuritySignature = _bool(smb.get("EnableSecuritySignature"))
    host.SMBRequireSecuritySignature = _bool(smb.get("RequireSecuritySignature"))

    wsh = _obj(data.get("WSHSettings"))
    host.WSHTrustPolicy = _str(wsh.get("TrustPolicy"))
    host.WSHEnabled = _bool(wsh.get("EnabledStatus"))
    host.WSHRemote = _bool(wsh.get("RemoteStatus"))

    winlogon = _obj(data.get("Winlogon"))
    host.DefaultUserName = _str(winlogon.get("DefaultUserName"))
    host.DefaultPassword = _decode_default_password(winlogon)
    host.AutoAdminLogon = _bool(winlogon.get("AutoAdminLogon"))
    host.ForceAutoLogon = _bool(winlogon.get("ForceAutoLogon"))
    host.DefaultDomain = _str(winlogon.get("DefaultDomainName") or winlogon.get("DefaultDomain"))
    return host


def _add_hotfixes(data, host):
    for h in _list(data.get("Hotfixes")):
        hf = Hotfix()
        hf.HotfixId = _str(h.get("id") or h.get("HotFixID"))
        hf.InstalledOnStr = _str(h.get("InstalledOn"))
        hf.InstalledOn = _date(h.get("InstalledOn"))
        hf.Description = _str(h.get("Description"))
        hf.Host = host
        db.session.add(hf)


def _add_products(data, host):
    for p in _list(data.get("InstalledProducts")):
        prod = Product()
        prod.Caption = _str(p.get("Caption"))
        prod.InstallDate = _str(p.get("InstallDate"))
        prod.Description = _str(p.get("Description"))
        prod.Vendor = _str(p.get("Vendor"))
        prod.Name = _str(p.get("Name"))
        prod.Version = _str(p.get("Version"))
        prod.InstallLocation = _str(p.get("InstallLocation"))
        prod.Host = host
        db.session.add(prod)


def _add_netadapters(data, host):
    for n in _list(data.get("NetAdapter")):
        na = NetAdapter()
        na.MacAddress = _str(n.get("MacAddress"))
        na.Status = _str(n.get("Status"))
        na.Name = _str(n.get("Name"))
        na.InterfaceDescription = _str(n.get("InterfaceDescription"))
        na.Host = host
        db.session.add(na)


def _add_netipaddresses(data, host):
    for n in _list(data.get("NetIPs")):
        ip = NetIPAddress()
        ip.AddressFamily = _str(n.get("AddressFamily"))
        ip.IP = _str(n.get("IP"))
        ip.Prefix = _str(n.get("Prefix"))
        ip.Type = _str(n.get("Type"))
        ip.InterfaceAlias = _str(n.get("InterfaceAlias"))
        ip.Host = host
        db.session.add(ip)


def _add_routes(data, host):
    for r in _list(data.get("Routes")):
        route = Route()
        route.AddressFamily = _str(r.get("AddressFamily"))
        route.DestinationPrefix = _str(r.get("DestinationPrefix"))
        route.InterfaceAlias = _str(r.get("InterfaceAlias"))
        route.NextHop = _str(r.get("NextHop"))
        route.RouteMetric = _str(r.get("RouteMetric"))
        route.IfIndex = _int(r.get("IfIndex", r.get("ifIndex")))
        route.InterfaceMetric = _int(r.get("InterfaceMetric"))
        route.IsStatic = _bool(r.get("IsStatic"))
        route.AdminDistance = _int(r.get("AdminDistance"))
        route.Host = host
        db.session.add(route)


def _add_ntp(data, host):
    ntp_settings = _obj(data.get("NTPSettings"))
    if not ntp_settings:
        return
    ntp = NTP()
    ntp.Server = _str(ntp_settings.get("Server"))
    ntp.Type = _str(ntp_settings.get("Type"))
    ntp.UpdateInterval = _int(ntp_settings.get("UpdateInterval"))
    ntp.Host = host
    db.session.add(ntp)


def _add_users(data, host):
    for u in _list(data.get("Users")):
        user = User()
        user.AccountType = _str(u.get("AccountType"))
        user.Domain = _str(u.get("Domain"))
        user.Disabled = _bool(u.get("Disabled"))
        user.LocalAccount = _bool(u.get("LocalAccount"))
        user.Name = _str(u.get("Name"))
        user.FullName = _str(u.get("FullName"))
        user.Description = _str(u.get("Description"))
        user.SID = _str(u.get("SID"))
        user.Lockout = _bool(u.get("Lockout"))
        user.PasswordChangeable = _bool(u.get("PasswordChangeable"))
        user.PasswordExpires = _bool(u.get("PasswordExpires"))
        user.PasswordRequired = _bool(u.get("PasswordRequired"))
        user.Host = host
        db.session.add(user)


def _add_groups(data, host):
    for g in _list(data.get("Groups")):
        group = Group()
        group.Name = _str(g.get("Name"))
        group.Caption = _str(g.get("Caption"))
        group.Description = _str(g.get("Description"))
        group.LocalAccount = _str(g.get("LocalAccount"))
        group.SID = _str(g.get("SID"))
        group.Host = host
        db.session.add(group)
        for m in _list(g.get("Members")):
            member = GroupMember()
            member.Name = _str(m.get("Name"))
            member.Domain = _str(m.get("Domain"))
            member.Caption = _str(m.get("Caption"))
            member.AccountType = _str(m.get("AccountType"))
            member.SID = _str(m.get("SID"))
            member.Group = group
            db.session.add(member)


def _add_shares(data, host):
    for s in _list(data.get("Shares")):
        share = Share()
        share.Name = _str(s.get("Name"))
        share.Path = _str(s.get("Path"))
        share.Description = _str(s.get("Description"))
        share.Host = host
        db.session.add(share)
        for a in _list(s.get("NTFSPermissions")):
            ntfs = ShareACLNTFS()
            ntfs.Name = _str(a.get("Name")) or share.Name
            ntfs.AccountName = _str(a.get("AccountName"))
            ntfs.AccessControlType = _str(a.get("AccessControlType"))
            ntfs.AccessRight = _str(a.get("AccessRight"))
            ntfs.Share = share
            db.session.add(ntfs)
        for a in _list(s.get("SharePermissions")):
            perm = ShareACL()
            perm.Name = _str(a.get("Name")) or share.Name
            perm.ScopeName = _str(a.get("ScopeName"))
            perm.AccountName = _str(a.get("AccountName"))
            perm.AccessControlType = _str(a.get("AccessControlType"))
            perm.AccessRight = _str(a.get("AccessRight"))
            perm.Share = share
            db.session.add(perm)


def _add_psversions(data, host):
    for p in _list(data.get("PSVersions")):
        v = PSInstalledVersions()
        v.PSVersion = _str(p.get("PowerShellVersion") or p.get("PSVersion") or p.get("Version"))
        v.PSPath = _str(p.get("PSPath"))
        v.ConsoleHostModuleName = _str(p.get("ConsoleHostModuleName"))
        v.PSCompatibleVersion = _str(p.get("PSCompatibleVersion"))
        v.RuntimeVersion = _str(p.get("RuntimeVersion"))
        v.Host = host
        db.session.add(v)


def _add_printers(data, host):
    for p in _list(data.get("Printers")):
        printer = Printer()
        printer.Name = _str(p.get("Name"))
        printer.ShareName = _str(p.get("ShareName"))
        printer.Type = _str(p.get("Type"))
        printer.DriverName = _str(p.get("DriverName"))
        printer.PortName = _str(p.get("PortName"))
        printer.Shared = _str(p.get("Shared"))
        printer.Published = _str(p.get("Published"))
        printer.Host = host
        db.session.add(printer)


def _add_defender(data, host):
    defender = _obj(data.get("DefenderInfo"))

    s = _obj(defender.get("MpComputerStatus"))
    if s:
        status = DefenderStatus()
        status.AMEngineVersion = _str(s.get("AMEngineVersion"))
        status.AMProductVersion = _str(s.get("AMProductVersion"))
        status.AMServiceEnabled = _bool(s.get("AMServiceEnabled"))
        status.AMServiceVersion = _str(s.get("AMServiceVersion"))
        status.AntispywareEnabled = _bool(s.get("AntispywareEnabled"))
        status.AntispywareSignatureLastUpdated = _str(s.get("AntispywareSignatureLastUpdated"))
        status.AntispywareSignatureVersion = _str(s.get("AntispywareSignatureVersion"))
        status.AntivirusEnabled = _bool(s.get("AntivirusEnabled"))
        status.AntivirusSignatureLastUpdated = _str(s.get("AntivirusSignatureLastUpdated"))
        status.AntivirusSignatureVersion = _str(s.get("AntivirusSignatureVersion"))
        status.BehaviorMonitorEnabled = _bool(s.get("BehaviorMonitorEnabled"))
        status.IoavProtectionEnabled = _bool(s.get("IoavProtectionEnabled"))
        status.IsVirtualMachine = _bool(s.get("IsVirtualMachine"))
        status.NISEnabled = _bool(s.get("NISEnabled"))
        status.NISEngineVersion = _str(s.get("NISEngineVersion"))
        status.NISSignatureLastUpdated = _str(s.get("NISSignatureLastUpdated"))
        status.NISSignatureVersion = _str(s.get("NISSignatureVersion"))
        status.OnAccessProtectionEnabled = _bool(s.get("OnAccessProtectionEnabled"))
        status.RealTimeProtectionEnabled = _bool(s.get("RealTimeProtectionEnabled"))
        status.Host = host
        db.session.add(status)

    p = _obj(defender.get("MpPreference"))
    if p:
        settings = DefenderSettings()
        for name in ("DisableArchiveScanning", "DisableAutoExclusions", "DisableBehaviorMonitoring",
                     "DisableBlockAtFirstSeen", "DisableCatchupFullScan", "DisableCatchupQuickScan",
                     "DisableEmailScanning", "DisableIntrusionPreventionSystem", "DisableIOAVProtection",
                     "DisableRealtimeMonitoring", "DisableRemovableDriveScanning", "DisableRestorePoint",
                     "DisableScanningMappedNetworkDrivesForFullScan", "DisableScanningNetworkFiles",
                     "DisableScriptScanning"):
            setattr(settings, name, _bool(p.get(name)))
        settings.EnableNetworkProtection = network_protection_or_none(p.get("EnableNetworkProtection"))
        settings.ExclusionPath = _str(p.get("ExclusionPath"))
        settings.ExclusionProcess = _str(p.get("ExclusionProcess"))
        settings.Host = host
        db.session.add(settings)


def _add_services(data, host):
    for s in _list(data.get("Services")):
        service = Service()
        service.Caption = _str(s.get("Caption"))
        service.Description = _str(s.get("Description"))
        service.Name = _str(s.get("Name"))
        service.StartMode = _str(s.get("StartMode"))
        service.PathName = _str(s.get("PathName"))
        service.Started = _bool(s.get("Started"))
        service.StartName = _str(s.get("StartName"))
        service.SystemName = _str(s.get("SystemName"))
        service.DisplayName = _str(s.get("DisplayName"))
        service.AcceptStop = _bool(s.get("AcceptStop"))
        service.AcceptPause = _bool(s.get("AcceptPause"))
        service.ProcessId = _str(s.get("ProcessId"))
        service.DelayedAutoStart = _bool(s.get("DelayedAutoStart"))
        service.Host = host
        db.session.add(service)

        perm_str = []
        for a in _list(s.get("BinaryPermissions")):
            acl = ServiceACL()
            acl.Name = _str(a.get("Name")) or service.Name
            acl.AccountName = _str(a.get("AccountName"))
            acl.AccessControlType = _str(a.get("AccessControlType"))
            acl.AccessRight = _str(a.get("AccessRight"))
            acl.Service = service
            db.session.add(acl)
            perm_str.append("{0}{1}{2}{3}".format(acl.Name, acl.AccountName, acl.AccessControlType, acl.AccessRight))
        service.BinaryPermissionsStr = "\n".join(perm_str) if perm_str else None


def _add_config_checks(data, host):
    for c in _list(data.get("ConfigCheckResults")):
        check = ConfigCheck()
        check.Component = _str(c.get("Component"))
        check.Name = _str(c.get("Name"))
        check.Method = _str(c.get("Method"))
        check.Key = _str(c.get("Key"))
        check.Value = _str(c.get("Value"))
        check.Result = _str(c.get("Result"))
        check.Message = _str(c.get("Message"))
        check.Host = host
        db.session.add(check)


def _add_registry_checks(data, host):
    for c in _list(data.get("RegistryCheckResults")):
        check = RegistryCheck()
        check.Category = _str(c.get("Category"))
        check.Name = _str(c.get("Name"))
        check.Description = _str(c.get("Description"))
        check.Tags = _str(c.get("Tags"))
        check.Path = _str(c.get("Path"))
        check.Key = _str(c.get("Key"))
        check.Expected = _str(c.get("Expected"))
        check.KeyExists = _bool(c.get("KeyExists"))
        check.ValueMatch = _bool(c.get("ValueMatch"))
        check.CurrentValue = _str(c.get("CurrentValue"))
        check.Host = host
        db.session.add(check)


def _add_file_exist_checks(data, host):
    for c in _list(data.get("FileChecksResults")):
        check = FileExistCheck()
        check.Name = _str(c.get("Name"))
        check.File = _str(c.get("File"))
        check.ExpectedHASH = _str(c.get("ExpectedHASH"))
        check.FileExist = _bool(c.get("FileExist"))
        check.HashMatch = _bool(c.get("HashMatch"))
        check.HashChecked = _bool(c.get("HashChecked"))
        check.CurrentHash = _str(c.get("CurrentHash"))
        check.Host = host
        db.session.add(check)


def _add_path_acl_checks(data, host):
    for c in _list(data.get("AclPathChecks")):
        check = PathACLCheck()
        check.Path = _str(c.get("Path"))
        check.Host = host
        db.session.add(check)

        perm_str = []
        for a in _list(c.get("ACLs")):
            acl = PathACL()
            acl.Name = _str(a.get("path") or a.get("Path")) or check.Path
            acl.AccountName = _str(a.get("AccountName"))
            acl.AccessControlType = _str(a.get("AccessControlType"))
            acl.AccessRight = _str(a.get("AccessRight"))
            acl.PathACLCheck = check
            db.session.add(acl)
            perm_str.append("{0}{1}{2}{3}".format(acl.Name, acl.AccountName, acl.AccessControlType, acl.AccessRight))
        check.ACLStr = "\n".join(perm_str) if perm_str else None


# Sections stored in separate tables. Each section is committed separately, so an error in one section does not
# prevent the import of the others.
SECTIONS = [
    ("Hotfixes", _add_hotfixes),
    ("InstalledProducts", _add_products),
    ("NetAdapter", _add_netadapters),
    ("NetIPs", _add_netipaddresses),
    ("Routes", _add_routes),
    ("NTPSettings", _add_ntp),
    ("Users", _add_users),
    ("Groups", _add_groups),
    ("Shares", _add_shares),
    ("PSVersions", _add_psversions),
    ("Printers", _add_printers),
    ("DefenderInfo", _add_defender),
    ("Services", _add_services),
    ("ConfigCheckResults", _add_config_checks),
    ("RegistryCheckResults", _add_registry_checks),
    ("FileChecksResults", _add_file_exist_checks),
    ("AclPathChecks", _add_path_acl_checks),
]


def sysinfo2db(data: dict):
    """
    Writes the data of one host (dictionary in the structure of the JSON file) to the database.

    :param data: dictionary with the collected information of one host
    :return: the created Host object or None if the host could not be created
    """
    try:
        host = _new_host(data)
        db.session.add(host)
        db.session.commit()
        db.session.refresh(host)
    except SQLAlchemyError as e:
        db.session.rollback()
        print("Error while creating Host. Error: {0}".format(str(e.__dict__.get('orig', e))))
        return None

    for name, func in SECTIONS:
        try:
            func(data, host)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            print("Error while creating {0}. Error: {1}".format(name, str(e.__dict__.get('orig', e))))
        except Exception as e:
            db.session.rollback()
            print("Error while importing {0}. Error: {1}".format(name, str(e)))
    return host


###################################################################################################################
# Entry points
###################################################################################################################
def import_sysinfo_xml(root) -> list:
    """
    Imports the XML document (root element "SystemInfoCollector") of the SystemInfoCollector >= 0.7.

    :param root: root element of the parsed XML document (lxml or ElementTree)
    :return: list of imported Host objects
    """
    hosts = []
    for data in xml2sysinfo(root):
        host = sysinfo2db(data)
        if host:
            hosts.append(host)
    return hosts


def import_sysinfo_json(data) -> list:
    """
    Imports the content of a JSON file created by the SystemInfoCollector.

    :param data: loaded JSON (dictionary of one host or list of dictionaries)
    :return: list of imported Host objects
    """
    hosts = []
    for d in (data if isinstance(data, list) else [data]):
        host = sysinfo2db(d)
        if host:
            hosts.append(host)
    return hosts


def load_json(raw: bytes):
    """ Loads JSON content. PowerShell may write UTF-8 with BOM or UTF-16 (Out-File in Windows PowerShell 5). """
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            return json.loads(raw.decode(encoding))
        except (UnicodeDecodeError, ValueError):
            continue
    raise ValueError("File is not a valid JSON file")
