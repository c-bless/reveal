import datetime
from sqlalchemy.exc import SQLAlchemyError

from systemdb.core.models.sysinfo import Hotfix
from systemdb.core.models.sysinfo import Host
from systemdb.core.models.sysinfo import Product
from systemdb.core.models.sysinfo import Group
from systemdb.core.models.sysinfo import User
from systemdb.core.models.sysinfo import Service
from systemdb.core.models.sysinfo import Share
from systemdb.core.models.sysinfo import NetAdapter
from systemdb.core.models.sysinfo import Printer
from systemdb.core.models.sysinfo import NetIPAddress
from systemdb.core.models.sysinfo import GroupMember
from systemdb.core.models.sysinfo import ShareACL
from systemdb.core.models.sysinfo import ShareACLNTFS
from systemdb.core.models.sysinfo import ServiceACL
from systemdb.core.models.sysinfo import PSInstalledVersions
from systemdb.core.models.sysinfo import DefenderSettings
from systemdb.core.models.sysinfo import ConfigCheck
from systemdb.core.models.sysinfo import RegistryCheck
from systemdb.core.extentions import db

from systemdb.core.importer.converter import str2bool_or_none


def import_sysinfo_collector(root):
    if root.tag == "SystemInfoCollector":
        for h in root.getchildren():
            host = import_host(h)


def import_host(root):
    if root.tag == "Host":
        host = host2db(root)
        if not host:
            print("Error while creating Host")
            return None
        for elem in root.getchildren():
            if "Hotfixes" == elem.tag:
                try:
                    hotfix2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Hotfixes. Error: {0}".format(str(e.__dict__['orig'])))
            if "Products" == elem.tag:
                try:
                    products2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Products. Error: {0}".format(str(e.__dict__['orig'])))
            if "Netadapters" == elem.tag:
                try:
                    netadapter2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Netadapters. Error: {0}".format(str(e.__dict__['orig'])))
            if "NetIPAddresses" == elem.tag:
                try:
                    netipaddresses2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating NetIPAddresses. Error: {0}".format(str(e.__dict__['orig'])))
            if "Services" == elem.tag:
                try:
                    services2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Services. Error: {0}".format(str(e.__dict__['orig'])))
            if "Users" == elem.tag:
                try:
                    users2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Users. Error: {0}".format(str(e.__dict__['orig'])))
            if "Groups" == elem.tag:
                try:
                    groups2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Groups. Error: {0}".format(str(e.__dict__['orig'])))
            if "Shares" == elem.tag:
                try:
                    shares2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Shares. Error: {0}".format(str(e.__dict__['orig'])))
            if "NetFirewallProfiles" == elem.tag:
                try:
                    fwprofile2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating NetFirewallProfiles. Error: {0}".format(str(e.__dict__['orig'])))
            if "WSUS" == elem.tag:
                try:
                    wsus2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating WSUS. Error: {0}".format(str(e.__dict__['orig'])))
            if "SMBSettings" == elem.tag:
                try:
                    smb2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating SMBSettings. Error: {0}".format(str(e.__dict__['orig'])))
            if "BIOS" == elem.tag:
                try:
                    bios2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating BIOS. Error: {0}".format(str(e.__dict__['orig'])))
            if "WSH" == elem.tag:
                try:
                    wsh2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating WSH. Error: {0}".format(str(e.__dict__['orig'])))
            if "PSVersions" == elem.tag:
                try:
                    psversions2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating PSVersions. Error: {0}".format(str(e.__dict__['orig'])))
            if "Printers" == elem.tag:
                try:
                    printers2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating Printers. Error: {0}".format(str(e.__dict__['orig'])))
            if "DefenderSettings" == elem.tag:
                try:
                    defenderSettings2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating DefenderSettings. Error: {0}".format(str(e.__dict__['orig'])))
            if "ConfigChecks" == elem.tag:
                try:
                    configchecks2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating ConfigChecks. Error: {0}".format(str(e.__dict__['orig'])))
            if "AdditionalRegistryChecks" == elem.tag:
                try:
                    registrychecks2db(elem, host)
                    db.session.commit()
                except SQLAlchemyError as e:
                    db.session.rollback()
                    print("Error while creating AdditionalRegistryChecks. Error: {0}".format(str(e.__dict__['orig'])))
        return host


def host2db(xml_element):
    try:
        host = Host()
        for e in xml_element.getchildren():
            # print("{0} {1}".format(e.tag, e.text))
            if "Hostname" == e.tag: host.Hostname = e.text
            if "Domain" == e.tag: host.Domain = e.text
            if "DomainRole" == e.tag: host.DomainRole = e.text
            if "OSVersion" == e.tag: host.OSVersion = e.text
            if "OSBuildNumber" == e.tag: host.OSBuildNumber = e.text
            if "OSName" == e.tag: host.OSName = e.text
            if "OSInstallDate" == e.tag: host.OSInstallDate = e.text
            if "OSProductType" == e.tag: host.OSProductType = e.text
            if "LogonServer" == e.tag: host.LogonServer = e.text
            if "TimeZone" == e.tag: host.TimeZone = e.text
            if "KeyboardLayout" == e.tag: host.KeyboardLayout = e.text
            if "HyperVisorPresent" == e.tag: host.HyperVisorPresent = str2bool_or_none(e.text)
            if "DeviceGuardSmartStatus" == e.tag: host.DeviceGuardSmartStatus = e.text
            if "PSVersion" == e.tag: host.PSVersion = e.text
            if "PSVersion2Installed" == e.tag: host.PS2Installed = str2bool_or_none(e.text)
            if "PSScriptBlockLogging" == e.tag: host.PSScriptBlockLogging = e.text
            if "SystemGroup" == e.tag: host.SystemGroup = e.text
            if "Location" == e.tag: host.Location = e.text
            if "Whoami" == e.tag : host.Whoami = e.text
            if "WhoamiIsAdmin" == e.tag : host.WhoamiIsAdmin = str2bool_or_none(e.text)
            if "Winlogon" == e.tag:
                for w in e.getchildren():
                    if "DefaultUserName" == w.tag: host.DefaultUserName = w.text
                    if "DefaultPassword" == w.tag: host.DefaultPassword = w.text
                    if "AutoAdminLogon" == w.tag: host.AutoAdminLogon = str2bool_or_none(w.text)
                    if "DefaultDomainName" == w.tag: host.DefaultDomain = w.text
                    if "ForceAutoLogon" == w.tag: host.ForceAutoLogon = str2bool_or_none(w.text)
        db.session.add(host)
        db.session.commit()
        db.session.refresh(host)
        return host
    except SQLAlchemyError as e:
        db.session.rollback()
        print("Error while creating Host. Error: {0}".format(str(e.__dict__['orig'])))
        return None


def hotfix2db(xml, host):
    if "Hotfixes" == xml.tag:
        try:
            lastupdate = xml.get("LastUpdate")
            host.LastUpdate = datetime.datetime.strptime(lastupdate, "%m/%d/%Y %H:%M:%S").date()
        except:
            pass
    for c in xml.getchildren():
        if "Hotfix" == c.tag:
            hf = Hotfix()
            hf.HotfixId = c.get("id")
            try:
                d = c.get("InstalledOn")
                hf.InstalledOn = datetime.datetime.strptime(d, "%m/%d/%Y %H:%M:%S").date()
            except:
                pass
            hf.Description = c.get("Description")
            hf.Host = host
            db.session.add(hf)


def products2db(xml, host):
    for c in xml.getchildren():
        if "Product" == c.tag:
            prod = Product()
            for i in c.getchildren():
                if "Caption" == i.tag: prod.Caption = i.text
                if "InstallDate" == i.tag: prod.InstallDate = i.text
                if "Description" == i.tag: prod.Description = i.text
                if "Vendor" == i.tag: prod.Vendor = i.text
                if "Name" == i.tag: prod.Name = i.text
                if "Version" == i.tag: prod.Version = i.text
                if "InstallLocation" == i.tag: prod.InstallLocation = i.text
            prod.Host = host
            db.session.add(prod)


def printers2db(xml, host):
    for c in xml.getchildren():
        if "Printer" == c.tag:
            printer = Printer()
            for i in c.getchildren():
                if "Name" == i.tag: printer.Name = i.text
                if "ShareName" == i.tag: printer.ShareName = i.text
                if "Type" == i.tag: printer.Type = i.text
                if "DriverName" == i.tag: printer.DriverName = i.text
                if "PortName" == i.tag: printer.PortName = i.text
                if "Shared" == i.tag: printer.Shared = i.text
                if "Published" == i.tag: printer.Published = i.text
            printer.Host = host
            db.session.add(printer)


def defenderSettings2db(xml, host):
    for i in xml.getchildren():
        setting = DefenderSettings()
        setting.Name == i.tag
        setting.Value = i.text
        setting.Host = host
        db.session.add(setting)


def netadapter2db(xml, host):
    for c in xml.getchildren():
        if "Netadapter" == c.tag:
            na = NetAdapter()
            na.MacAddress = c.get("MacAddress")
            na.Status = c.get("Status")
            na.Name = c.get("Name")
            na.InterfaceDescription = c.get("InterfaceDescription")
            na.Host = host
            db.session.add(na)


def services2db(xml, host):
    for c in xml.getchildren():
        if "Service" == c.tag:
            service = Service()
            for i in c.getchildren():
                if "Caption" == i.tag: service.Caption = i.text
                if "Description" == i.tag: service.Description = i.text
                if "Name" == i.tag: service.Name = i.text
                if "StartMode" == i.tag: service.StartMode = i.text
                if "PathName" == i.tag: service.PathName = i.text
                if "Started" == i.tag: service.Started = i.text
                if "StartName" == i.tag: service.StartName = i.text
                if "SystemName" == i.tag: service.SystemName = i.text
                if "DisplayName" == i.tag: service.DisplayName = i.text
                if "Running" == i.tag: service.Running = i.text
                if "AcceptStop" == i.tag: service.AcceptStop = i.text
                if "AcceptPause" == i.tag: service.AcceptPause = i.text
                if "ProcessId" == i.tag: service.ProcessId = i.text
                if "DelayedAutoStart" == i.tag: service.DelayedAutoStart = i.text
            service.Host = host
            db.session.add(service)
            #db.session.commit()
            #db.session.refresh(service)
            for i in c.getchildren():
                if "BinaryPermissions" == i.tag:
                    childs = i.getchildren()
                    if len(childs) > 0:
                        perm_str =[]
                        for c in childs:
                            if "Permission" == c.tag:
                                ntfs = ServiceACL()
                                ntfs.Name = c.get("Name")
                                ntfs.AccountName = c.get("AccountName")
                                ntfs.AccessControlType = c.get("AccessControlType")
                                ntfs.AccessRight = c.get("AccessRight")
                                ntfs.Service = service
                                db.session.add(ntfs)
                                o = "{0}{1}{2}{3}".format(ntfs.Name, ntfs.AccountName, ntfs.AccessControlType, ntfs.AccessRight)
                                perm_str.append(o)
                        service.BinaryPermissionsStr = "\n".join(perm_str)
                    else:
                        service.BinaryPermissionsStr = i.text
                    db.session.add(service)


def netipaddresses2db(xml, host):
    for c in xml.getchildren():
        if "NetIPAddress" == c.tag:
            n = NetIPAddress()
            n.AddressFamily = c.get("AddressFamily")
            n.IP = c.get("IP")
            n.Prefix = c.get("Prefix")
            n.Type = c.get("Type")
            n.InterfaceAlias = c.get("InterfaceAlias")
            n.Host = host
            db.session.add(n)



def users2db(xml, host):
    for c in xml.getchildren():
        if "User" == c.tag:
            user = User()
            for i in c.getchildren():
                if "AccountType" == i.tag: user.AccountType = i.text
                if "Domain" == i.tag: user.Domain = i.text
                if "Disabled" == i.tag: user.Disabled = str2bool_or_none(i.text)
                if "LocalAccount" == i.tag: user.LocalAccount = str2bool_or_none(i.text)
                if "Name" == i.tag: user.Name = i.text
                if "FullName" == i.tag: user.FullName = i.text
                if "Description" == i.tag: user.Description = i.text
                if "SID" == i.tag: user.SID = i.text
                if "Lockout" == i.tag: user.Lockout = str2bool_or_none(i.text)
                if "PasswordChanged" == i.tag: user.PasswordChanged = i.text
                if "PasswordRequired" == i.tag: user.PasswordRequired = str2bool_or_none(i.text)
            user.Host = host
            db.session.add(user)



def groups2db(xml, host):
    for c in xml.getchildren():
        if "Group" == c.tag:
            group = Group()
            for i in c.getchildren():
                if "Name" == i.tag: group.Name = i.text
                if "Caption" == i.tag: group.Caption = i.text
                if "Description" == i.tag: group.Description = i.text
                if "LocalAccount" == i.tag: group.LocalAccount = i.text
                if "SID" == i.tag: group.SID = i.text
            group.Host = host
            db.session.add(group)
            #db.session.commit()
            #db.session.refresh(group)
            for i in c.getchildren():
                if "Members" == i.tag:
                    for m in i.getchildren():
                        member = GroupMember()
                        for a in m.getchildren():
                            if "Name" == a.tag: member.Name = a.text
                            if "Domain" == a.tag: member.Domain = a.text
                            if "Caption" == a.tag: member.Caption = a.text
                            if "AccountType" == a.tag: member.AccountType = a.text
                            if "SID" == a.tag: member.SID = a.text
                        member.Group = group
                        db.session.add(member)



def shares2db(xml, host):
    for c in xml.getchildren():
        if "Share" == c.tag:
            try:
                share = Share()
                for i in c.getchildren():
                    if "Name" == i.tag: share.Name = i.text
                    if "Path" == i.tag: share.Path = i.text
                    if "Description" == i.tag: share.Description = i.text
                share.Host = host
                db.session.add(share)

                for i in c.getchildren():
                    if "NTFSPermissions" == i.tag:
                        for n in i.getchildren():
                            if "Permission" == n.tag:
                                ntfs = ShareACLNTFS()
                                ntfs.Name = n.get("Name")
                                ntfs.AccountName = n.get("AccountName")
                                ntfs.AccessControlType = n.get("AccessControlType")
                                ntfs.AccessRight = n.get("AccessRight")
                                ntfs.Share = share
                                # add the object to the transaction. commit is done later
                                db.session.add(ntfs)
                    if "SharePermissions" == i.tag:
                        for n in i.getchildren():
                            if "Permission" == n.tag:
                                perm = ShareACL()
                                perm.Name = n.get("Name")
                                perm.ScopeName = n.get("ScopeName")
                                perm.AccountName = n.get("AccountName")
                                perm.AccessControlType = n.get("AccessControlType")
                                perm.AccessRight = n.get("AccessRight")
                                perm.Share = share
                                # add the object to the transaction. commit is done later
                                db.session.add(perm)
                # commit all permission objects for the share
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                print("Error while creating Share. Error: {0}".format(str(e.__dict__['orig'])))


def fwprofile2db(xml, host):
    """
    This function parses the NetFirewallProfiles-Tag and adds the FwProfileDomain, FwProfilePrivate and FwProfilePublic
    attributes on the host object which is that updated in the database.


        <NetFirewallProfiles>
            <FwProfile Name="Domain" Enabled="True" />
            <FwProfile Name="Private" Enabled="True" />
            <FwProfile Name="Public" Enabled="True" />
        </NetFirewallProfiles>
    

    :param xml: XML-Tag "NetFirewallProfiles"
    :param host: host database object
    :return:
    """
    for c in xml.getchildren():
        if "FwProfile" == c.tag:
            name = c.get("Name")
            enabled = c.get("Enabled")
            if name == "Domain":
                host.FwProfileDomain = str2bool_or_none(enabled)
            if name == "Private":
                host.FwProfilePrivate = str2bool_or_none(enabled)
            if name == "Public":
                host.FwProfilePublic = str2bool_or_none(enabled)


def wsus2db(xml, host):
    # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd939844(v=ws.10)?redirectedfrom=MSDN
    for e in xml.getchildren():
        if "AcceptTrustedPublisherCerts" == e.tag: host.AcceptTrustedPublisherCerts = e.text
        if "DisableWindowsUpdateAccess" == e.tag: host.DisableWindowsUpdateAccess = e.text
        if "ElevateNonAdmins" == e.tag: host.ElevateNonAdmins = e.text
        if "TargetGroup" == e.tag: host.TargetGroup = e.text
        if "TargetGroupEnabled" == e.tag: host.TargetGroupEnabled = e.text
        if "WUServer" == e.tag: host.WUServer = e.text
        if "WUStatusServer" == e.tag: host.WUStatusServer = e.text


def smb2db(xml, host):
    for e in xml.getchildren():
        if "SMB1Enabled" == e.tag: host.SMBv1Enabled = str2bool_or_none(e.text)
        if "SMB2Enabled" == e.tag: host.SMBv2Enabled = str2bool_or_none(e.text)
        if "EncryptData" == e.tag: host.SMBEncryptData = str2bool_or_none(e.text)
        if "EnableSecuritySignature" == e.tag: host.SMBEnableSecuritySignature = str2bool_or_none(e.text)
        if "RequireSecuritySignature" == e.tag: host.SMBRequireSecuritySignature = str2bool_or_none(e.text)



def wsh2db(xml, host):
    for e in xml.getchildren():
        if "TrustPolicy" == e.tag: host.WSHTrustPolicy = e.text
        if "EnabledStatus" == e.tag: host.WSHEnabled = str2bool_or_none(e.text)
        if "RemoteStatus" == e.tag: host.WSHRemote = str2bool_or_none(e.text)



def bios2db(xml, host):
    host.BiosManufacturer = xml.get("Manufacturer")
    host.BiosName = xml.get("Name")
    host.BiosVersion = xml.get("Version")
    host.BiosSerial = xml.get("Serial")



def psversions2db(xml, host):
    for e in xml.getchildren():
        if "PSVersion" == e.tag:
            v = PSInstalledVersions()
            v.PSVersion = e.get("PSVersion")
            v.PSPath  = e.get("PSPath")
            v.ConsoleHostModuleName = e.get("ConsoleHostModuleName")
            v.PSCompatibleVersion = e.get("PSCompatibleVersion")
            v.RuntimeVersion = e.get("RuntimeVersion")
            v.Host = host
            db.session.add(v)


def configchecks2db(xml, host):
    for e in xml.getchildren():
        if "ConfigCheck" == e.tag:
            check = ConfigCheck()
            check.Component = e.get("Component")
            check.Name = e.get("Name")
            check.Method = e.get("Method")
            for c in e.getchildren():
                if "Key" == c.tag: check.Key = c.text
                if "Value" == c.tag: check.Value = c.text
                if "Result" == c.tag: check.Result = c.text
                if "Message" == c.tag: check.Message = c.text
            check.Host = host
            db.session.add(check)


def registrychecks2db(xml, host):
    for e in xml.getchildren():
        if "RegistryCheck" == e.tag:
            check = RegistryCheck()
            check.Category = e.get("Category")
            check.Name = e.get("Name")
            for c in e.getchildren():
                if "Description" == c.tag: check.Description = c.text
                if "Tags" == c.tag: check.Tags = c.text
                if "Path" == c.tag: check.Path = c.text
                if "Key" == c.tag: check.Key = c.text
                if "Expected" == c.tag: check.Expected = c.text
                if "KeyExists" == c.tag: check.KeyExists = str2bool_or_none(c.text)
                if "ValueMatch" == c.tag: check.ValueMatch = str2bool_or_none(c.text)
                if "CurrentValue" == c.tag: check.CurrentValue = c.text
            check.Host = host
            db.session.add(check)
