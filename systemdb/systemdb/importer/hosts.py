from ..core.sysinfo_models import  Hotfix, Host, Product, Group, User, Service, Share, NetAdapter
from ..core.sysinfo_models import NetIPAddress, GroupMember, ShareACL, ShareACLNTFS
from ..core.db import db


def import_sysinfo_collector(root):
    if root.tag == "SystemInfoCollector":
        for h in root.getchildren():
            host = import_host(h)


def import_host(root):
    if root.tag == "Host":
        host = host2db(root)
        for e in root.getchildren():
            if "Hotfixes" == e.tag:
                hotfix2db(e, host)
            if "Products" == e.tag:
                products2db(e, host)
            if "Netadapters" == e.tag:
                netadapter2db(e, host)
            if "NetIPAddresses" == e.tag:
                netipaddresses2db(e, host)
            if "Services" == e.tag:
                services2db(e, host)
            if "Users" == e.tag:
                users2db(e, host)
            if "Groups" == e.tag:
                groups2db(e, host)
            if "Shares" == e.tag:
                shares2db(e, host)
        return host


def host2db(xml_element):
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
        if "HyperVisorPresent" == e.tag: host.HyperVisorPresent = e.text
        if "DeviceGuardSmartStatus" == e.tag: host.DeviceGuardSmartStatus = e.text
        if "PSVersion" == e.tag: host.PSVersion = e.text
        if "Winlogon" == e.tag:
            for w in e.getchildren():
                if "DefaultUserName" == w.tag: host.DefaultUserName = w.text
                if "DefaultPassword" == w.tag: host.DefaultPassword = w.text
                if "AutoAdminLogon" == w.tag: host.AutoAdminLogon = w.text
                if "DefaultDomain" == w.tag: host.DefaultDomain = w.text
                if "ForceAutoLogon" == w.tag: host.ForceAutoLogon = w.text
    db.session.add(host)
    db.session.commit()
    db.session.refresh(host)
    return host


def hotfix2db(xml, host):
    for c in xml.getchildren():
        if "Hotfix" == c.tag:
            hf = Hotfix()
            hf.HotfixId = c.get("id")
            hf.InstalledOn = c.get("InstalledOn")
            hf.Description = c.get("Description")
            hf.Host_id = host.id
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
            prod.Host_id = host.id
            db.session.add(prod)


def netadapter2db(xml, host):
    for c in xml.getchildren():
        if "Netadapter" == c.tag:
            na = NetAdapter()
            na.MacAddress = c.get("MacAddress")
            na.Status = c.get("Status")
            na.Name = c.get("Name")
            na.InterfaceDescription = c.get("InterfaceDescription")
            na.Host_id = host.id
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
                if "BinaryPermissions" == i.tag: service.BinaryPermissions = i.text
            service.Host_id = host.id
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
            n.Host_id = host.id
            db.session.add(n)


def users2db(xml, host):
    for c in xml.getchildren():
        if "User" == c.tag:
            user = User()
            for i in c.getchildren():
                if "AccountType" == i.tag: user.AccountType = i.text
                if "Domain" == i.tag: user.Domain = i.text
                if "Disabled" == i.tag: user.Disabled = i.text
                if "LocalAccount" == i.tag: user.LocalAccount = i.text
                if "Name" == i.tag: user.Name = i.text
                if "FullName" == i.tag: user.FullName = i.text
                if "Description" == i.tag: user.Description = i.text
                if "SID" == i.tag: user.SID = i.text
                if "Lockout" == i.tag: user.Lockout = i.text
                if "PasswordChanged" == i.tag: user.PasswordChanged = i.text
                if "PasswordRequired" == i.tag: user.PasswordRequired = i.text
            user.Host_id = host.id
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
            group.Host_id = host.id
            db.session.add(group)
            db.session.commit()
            db.session.refresh(group)
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
                        member.Group_id = group.id
                        db.session.add(member)

def shares2db(xml, host):
    for c in xml.getchildren():
        if "Share" == c.tag:
            share = Share()
            for i in c.getchildren():
                if "Name" == i.tag: share.Name = i.text
                if "Path" == i.tag: share.Path = i.text
                if "Description" == i.tag: share.Description = i.text
                if "NTFSPermission" == i.tag: share.NTFSPermission = i.text
                if "SharePermission" == i.tag: share.SharePermission = i.text
            share.Host_id = host.id
            db.session.add(share)
            db.session.commit()
            db.session.refresh(share)
            for i in c.getchildren():
                if "NTFSPermissions" == i.tag:
                    for n in i.getchildren():
                        if "Permission" == n.tag:
                            ntfs = ShareACLNTFS()
                            ntfs.Name = n.get("Name")
                            ntfs.AccountName = n.get("AccountName")
                            ntfs.AccessControlType = n.get("AccessControlType")
                            ntfs.AccessRight = n.get("AccessRight")
                            ntfs.Share_id = share.id
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
                            perm.Share_id = share.id
                            db.session.add(perm)