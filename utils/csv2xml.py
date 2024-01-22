#!/usr/bin/env python

import os
import csv
import argparse
from lxml import etree


def add_hostinfo(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            for row in reader:
                if "Version" in header:
                    version = etree.SubElement(host, "version")
                    version.text = row['Version']
                if "SystemGroup" in header:
                    systemgroup = etree.SubElement(host, "SystemGroup")
                    systemgroup.text = row['SystemGroup']
                if "Location" in header:
                    location = etree.SubElement(host, "Location")
                    location.text = row['Location']
                if "Label" in header:
                    label = etree.SubElement(host, "Label")
                    label.text = row['Label']
                if "Hostname" in header:
                    hostname = etree.SubElement(host, "Hostname")
                    hostname.text = row['Hostname']
                if "OSBuildNumber" in header:
                    build_number = etree.SubElement(host, "OSBuildNumber")
                    build_number.text = row['OSBuildNumber']
                if "OSVersion" in header:
                    os_version = etree.SubElement(host, "OSVersion")
                    os_version.text = row['OSVersion']
                if "OSName" in header:
                    os_name = etree.SubElement(host, "OSName")
                    os_name.text = row['OSName']
                if "OSInstallDate" in header:
                    os_instaldate = etree.SubElement(host, "OSInstallDate")
                    os_instaldate.text = row['OSInstallDate']
                if "Domain" in header:
                    domain = etree.SubElement(host, "Domain")
                    domain.text = row['Domain']
                if "DomainRole" in header:
                    domain_role = etree.SubElement(host, "DomainRole")
                    domain_role.text = row['DomainRole']
                if "Manufacturer" in header:
                    manufacturer = etree.SubElement(host, "Manufacturer")
                    manufacturer.text = row['Manufacturer']
                if "TimeZone" in header:
                    tz = etree.SubElement(host, "TimeZone")
                    tz.text = row['TimeZone']
                if "Model" in header:
                    model = etree.SubElement(host, "Model")
                    model.text = row['Model']
                if "HyperVisorPresent" in header:
                    hypervisor_present = etree.SubElement(host, "HyperVisorPresent")
                    hypervisor_present.text = row['HyperVisorPresent']
                if "PrimaryOwnerName" in header:
                    owner = etree.SubElement(host, "PrimaryOwnerName")
                    owner.text = row['PrimaryOwnerName']
                if "Whoami" in header:
                    whoami = etree.SubElement(host, "Whoami")
                    whoami.text = row['Whoami']
                if "WhoamiIsAdmin" in header:
                    is_admin = etree.SubElement(host, "WhoamiIsAdmin")
                    is_admin.text = row['WhoamiIsAdmin']
                if "PSVersion" in header:
                    ps_version = etree.SubElement(host, "PSVersion")
                    ps_version.text = row['PSVersion']
                if "LastUpdate" in header:
                    last_update = etree.SubElement(host, "LastUpdate")
                    last_update.text = row['LastUpdate']
                if "PSVersion2Installed" in header:
                    ps2_installed = etree.SubElement(host, "PSVersion2Installed")
                    ps2_installed.text = row['PSVersion2Installed']
    except:
        pass

def add_bios(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            bios = etree.SubElement(host, "BIOS")
            for row in reader:
                if "Version" in header:
                    bios.set("version", row['Version'])
                if "Manufacturer" in header:
                    bios.set("Manufacturer", row['Manufacturer'])
                if "Name" in header:
                    bios.set("Name", row['Name'])
                if "SerialNumber" in header:
                    bios.set("SerialNumber", row['SerialNumber'])
    except:
        pass

def add_config_checks(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            config_checks = etree.SubElement(host, "ConfigChecks")
            for row in reader:
                cc = etree.SubElement(config_checks, "ConfigCheck")
                if "Component" in header:
                    cc.set("Component", row['Component'])
                if "Method" in header:
                    cc.set("Method", row['Method'])
                if "Name" in header:
                    cc.set("Name", row['Name'])
                if "Key" in header:
                    key = etree.SubElement(cc, "Key")
                    key.text = row['Key']
                if "Value" in header:
                    value = etree.SubElement(cc, "Value")
                    value.text = row['Value']
                if "Result" in header:
                    result = etree.SubElement(cc, "Result")
                    result.text = row['Result']
                if "Message" in header:
                    message = etree.SubElement(cc, "Message")
                    message.text = row['Message']
    except:
        pass

def add_hotfixes(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            hotfixes = etree.SubElement(host, "Hotfixes")
            for row in reader:
                hf = etree.SubElement(hotfixes, "Hotfix")
                if "HotFixId" in header:
                    hf.set("id", row['HotFixId'])
                if "InstalledOn" in header:
                    hf.set("InstalledOn", row['InstalledOn'])
                if "Description" in header:
                    hf.set("Description", row['Description'])
    except:
        pass

def add_netadapter(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            adapters = etree.SubElement(host, "Netadapters")
            for row in reader:
                na = etree.SubElement(adapters, "Netadapter")
                if "MacAddress" in header:
                    na.set("MacAddress", row['MacAddress'])
                if "Status" in header:
                    na.set("Status", row['Status'])
                if "Name" in header:
                    na.set("Name", row['Name'])
                if "InterfaceDescription" in header:
                    na.set("InterfaceDescription", row['InterfaceDescription'])
    except:
        pass

def add_netips(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            adapters = etree.SubElement(host, "NetIPAddresses")
            for row in reader:
                na = etree.SubElement(adapters, "NetIPAddress")
                if "AddressFamily" in header:
                    na.set("AddressFamily", row['AddressFamily'])
                if "IPAddress" in header:
                    na.set("IP", row['IPAddress'])
                if "Type" in header:
                    na.set("Type", row['Type'])
                if "PrefixLength" in header:
                    na.set("Prefix", row['PrefixLength'])
                if "InterfaceAlias" in header:
                    na.set("InterfaceAlias", row['InterfaceAlias'])
    except:
        pass


def add_services(host: etree.Element, entry: os.DirEntry):
    service_acl_path = entry.path.replace("-services.csv", "-service_acls.csv")
    service_acl_elements = {}
    with open(service_acl_path, "r") as service_acls:
        service_acls.__next__()
        sa_reader = csv.DictReader(service_acls)
        sa_header = sa_reader.fieldnames
        sname = ""
        for sa_row in sa_reader:
            permission = etree.Element("Permission")
            if "Name" in sa_header:
                sname = sa_row['Name']
                permission.set("Name", sa_row['Name'])
            if "Executable" in sa_header:
                permission.set("Executable", sa_row['Executable'])
            if "AccountName" in sa_header:
                permission.set("AccountName", sa_row['AccountName'])
            if "AccessControlType" in sa_header:
                permission.set("AccessControlType", sa_row['AccessControlType'])
            if "AccessRight" in sa_header:
                permission.set("AccessRight", sa_row['AccessRight'])
            if sname in service_acl_elements:
                service_acl_elements[sname].append(permission)
            else:
                service_acl_elements[sname] = [permission]
    with open(entry.path, mode='r') as csv_file:
        csv_file.__next__()  # skip first row, This should contain PowerShell type information
        reader = csv.DictReader(csv_file)
        header = reader.fieldnames
        services = etree.SubElement(host, "Services")
        for row in reader:
            service = etree.SubElement(services, "Service")
            if "Caption" in header:
                caption = etree.SubElement(service, "Caption")
                caption.text = row['Caption']
            if "Description" in header:
                desc = etree.SubElement(service, "Description")
                desc.text = row['Description']
            if "Name" in header:
                name = etree.SubElement(service, "Name")
                name.text = row['Name']
                if row['Name'] in service_acl_elements:
                    bp = etree.SubElement(service, "BinaryPermissions")
                    e = ""
                    for s in service_acl_elements[row['Name']]:
                        e = s.get("Executable")
                        bp.append(s)
                    executable = etree.SubElement(service, "Executable")
                    executable.text = e
            if "StartMode" in header:
                mode = etree.SubElement(service, "StartMode")
                mode.text = row['StartMode']
            if "PathName" in header:
                pathname = etree.SubElement(service, "PathName")
                pathname.text = row['PathName']
            if "Started" in header:
                started = etree.SubElement(service, "Started")
                started.text = row['Started']
            if "StartName" in header:
                startname = etree.SubElement(service, "StartName")
                startname.text = row['StartName']
            if "DisplayName" in header:
                dn = etree.SubElement(service, "DisplayName")
                dn.text = row['DisplayName']
            if "Running" in header:
                running = etree.SubElement(service, "Running")
                running.text = row['Running']
            if "AcceptStop" in header:
                accept_stop = etree.SubElement(service, "AcceptStop")
                accept_stop.text = row['AcceptStop']
            if "AcceptPause" in header:
                accept_pause = etree.SubElement(service, "AcceptPause")
                accept_pause.text = row['AcceptPause']
            if "ProcessId" in header:
                pid = etree.SubElement(service, "ProcessId")
                pid.text = row['ProcessId']
            if "DelayedAutoStart" in header:
                delayed_start = etree.SubElement(service, "DelayedAutoStart")
                delayed_start.text = row['DelayedAutoStart']


def add_users(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            users = etree.SubElement(host, "Users")
            for row in reader:
                user = etree.SubElement(users, "User")
                if "AccountType" in header:
                    account_type = etree.SubElement(user, "AccountType")
                    account_type.text = row['AccountType']
                if "Domain" in header:
                    domain = etree.SubElement(user, "Domain")
                    domain.text = row['Domain']
                if "Disabled" in header:
                    disabled = etree.SubElement(user, "Disabled")
                    disabled.text = row['Disabled']
                if "LocalAccount" in header:
                    local_account = etree.SubElement(user, "LocalAccount")
                    local_account.text = row['LocalAccount']
                if "Name" in header:
                    name = etree.SubElement(user, "Name")
                    name.text = row['Name']
                if "FullName" in header:
                    fname = etree.SubElement(user, "FullName")
                    fname.text = row['FullName']
                if "Description" in header:
                    desc = etree.SubElement(user, "Description")
                    desc.text = row['Description']
                if "SID" in header:
                    sid = etree.SubElement(user, "SID")
                    sid.text = row['SID']
                if "Lockout" in header:
                    lockout = etree.SubElement(user, "Lockout")
                    lockout.text = row['Lockout']
                if "PasswordChanged" in header:
                    pw_changed = etree.SubElement(user, "PasswordChanged")
                    pw_changed.text = row['PasswordChanged']
                if "add_servicesPasswordRequired" in header:
                    pw_required = etree.SubElement(user, "PasswordRequired")
                    pw_required.text = row['PasswordRequired']
    except:
        pass

def add_groups(host: etree.Element, entry: os.DirEntry):
    members_path = entry.path.replace("-groups.csv", "-group_members.csv")
    members_elements = {}
    with open(members_path, "r") as members_file:
        members_file.__next__()
        m_reader = csv.DictReader(members_file)
        m_header = m_reader.fieldnames
        gname = ""
        for m_row in m_reader:
            member = etree.Element("Member")
            if "Groupname" in m_header:
                gname = m_row['Groupname']
                member.set("Groupname", m_row['Groupname'])
            if "Name" in m_header:
                member.set("Name", m_row['Name'])
            if "AccountType" in m_header:
                member.set("AccountType", m_row['AccountType'])
            if "Domain" in m_header:
                member.set("Domain", m_row['Domain'])
            if "SID" in m_header:
                member.set("SID", m_row['SID'])
            if "Caption" in m_header:
                member.set("Caption", m_row['Caption'])
            if gname in members_elements:
                members_elements[gname].append(member)
            else:
                members_elements[gname] = [member]
    with open(entry.path, mode='r') as csv_file:
        csv_file.__next__()  # skip first row, This should contain PowerShell type information
        reader = csv.DictReader(csv_file)
        header = reader.fieldnames
        groups = etree.SubElement(host, "Groups")
        for row in reader:
            group = etree.SubElement(groups, "Group")
            if "Name" in header:
                name = etree.SubElement(group, "Name")
                name.text = row['Name']
                if row['Name'] in members_elements:
                    ml = etree.SubElement(group, "Members")
                    for m in members_elements[row['Name']]:
                        ml.append(m)
            if "Caption" in header:
                caption = etree.SubElement(group, "Caption")
                caption.text = row['Caption']
            if "Description" in header:
                desc = etree.SubElement(group, "Description")
                desc.text = row['Description']
            if "LocalAccount" in header:
                local_account = etree.SubElement(group, "LocalAccount")
                local_account.text = row['LocalAccount']
            if "SID" in header:
                sid = etree.SubElement(group, "SID")
                sid.text = row['SID']

def add_fw_profiles(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            profiles = etree.SubElement(host, "NetFirewallProfiles")
            for row in reader:
                profile = etree.SubElement(profiles, "FwProfile")
                if "Name" in header:
                    profile.set("Name", row['Name'])
                if "Enabled" in header:
                    profile.set("Enabled", row['Enabled'])
    except:
        pass

def add_ntp(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            ntp = etree.SubElement(host, "NTP")
            for row in reader:
                if "Server" in header:
                    server = etree.SubElement(ntp, "Server")
                    server.text = row['Server']
                if "Type" in header:
                    type = etree.SubElement(ntp, "Type")
                    type.text = row['Type']
                if "UpdateInterval" in header:
                    update_interval = etree.SubElement(ntp, "UpdateInterval")
                    update_interval.text = row['UpdateInterval']
    except:
        pass

def add_smb(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            smb = etree.SubElement(host, "SMB")
            for row in reader:
                if "SMB1Enabled" in header:
                    smb1 = etree.SubElement(smb, "SMB1Enabled")
                    smb1.text = row['SMB1Enabled']
                if "SMB2Enabled" in header:
                    smb2 = etree.SubElement(smb, "SMB2Enabled")
                    smb2.text = row['SMB2Enabled']
                if "EncryptData" in header:
                    encrypt_data = etree.SubElement(smb, "EncryptData")
                    encrypt_data.text = row['EncryptData']
                if "EnableSecuritySignature" in header:
                    enable_sec_sig = etree.SubElement(smb, "EnableSecuritySignature")
                    enable_sec_sig.text = row['EnableSecuritySignature']
                if "RequireSecuritySignature" in header:
                    require_sec_sig = etree.SubElement(smb, "RequireSecuritySignature")
                    require_sec_sig.text = row['RequireSecuritySignature']
    except:
        pass

def add_wsus(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            wsus = etree.SubElement(host, "WSUS")
            for row in reader:
                if "AcceptTrustedPublisherCerts" in header:
                    accept_trusted = etree.SubElement(wsus, "AcceptTrustedPublisherCerts")
                    accept_trusted.text = row['AcceptTrustedPublisherCerts']
                if "ElevateNonAdmins" in header:
                    elevate_none_admin = etree.SubElement(wsus, "ElevateNonAdmins")
                    elevate_none_admin.text = row['ElevateNonAdmins']
                if "WUServer" in header:
                    server = etree.SubElement(wsus, "WUServer")
                    server.text = row['WUServer']
                if "WUStatusServer" in header:
                    status_server = etree.SubElement(wsus, "WUStatusServer")
                    status_server.text = row['WUStatusServer']
                if "TargetGroupEnabled" in header:
                    target_grp_enabled = etree.SubElement(wsus, "TargetGroupEnabled")
                    target_grp_enabled.text = row['TargetGroupEnabled']
                if "TargetGroup" in header:
                    target_grp = etree.SubElement(wsus, "TargetGroup")
                    target_grp.text = row['TargetGroup']
                if "DisableWindowsUpdateAccess" in header:
                    dis_update_access = etree.SubElement(wsus, "DisableWindowsUpdateAccess")
                    dis_update_access.text = row['DisableWindowsUpdateAccess']
    except:
        pass

def add_printers(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            printers = etree.SubElement(host, "Printers")
            for row in reader:
                printer = etree.SubElement(printers, "Printer")
                if "ShareName" in header:
                    shareName = etree.SubElement(printer, "ShareName")
                    shareName.text = row['ShareName']
                if "Type" in header:
                    t = etree.SubElement(printer, "Type")
                    t.text = row['Type']
                if "DriverName" in header:
                    dn = etree.SubElement(printer, "DriverName")
                    dn.text = row['DriverName']
                if "PortName" in header:
                    pn = etree.SubElement(printer, "PortName")
                    pn.text = row['PortName']
                if "Shared" in header:
                    shared = etree.SubElement(printer, "Shared")
                    shared.text = row['Shared']
                if "Published" in header:
                    published = etree.SubElement(printer, "Published")
                    published.text = row['Published']
    except:
        pass


def add_products(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            products = etree.SubElement(host, "Products")
            for row in reader:
                product = etree.SubElement(products, "Product")
                if "Caption" in header:
                    caption = etree.SubElement(product, "Caption")
                    caption.text = row['Caption']
                if "InstallDate" in header:
                    installdate = etree.SubElement(product, "InstallDate")
                    installdate.text = row['InstallDate']
                if "Description" in header:
                    desc = etree.SubElement(product, "Description")
                    desc.text = row['Description']
                if "Vendor" in header:
                    vendor = etree.SubElement(product, "Vendor")
                    vendor.text = row['Vendor']
                if "Name" in header:
                    name = etree.SubElement(product, "Name")
                    name.text = row['Name']
                if "Version" in header:
                    version = etree.SubElement(product, "Version")
                    version.text = row['Version']
                if "InstallLocation" in header:
                    install_loc = etree.SubElement(product, "InstallLocation")
                    install_loc.text = row['InstallLocation']
    except:
        pass

def add_winlogon(host: etree.Element, entry: os.DirEntry):
    with open(entry.path, mode='r') as csv_file:
        csv_file.__next__()  # skip first row, This should contain PowerShell type information
        reader = csv.DictReader(csv_file)
        header = reader.fieldnames
        winlogon = etree.SubElement(host, "Winlogon")
        for row in reader:
            if "DefaultUserName" in header:
                username = etree.SubElement(winlogon, "DefaultUserName")
                username.text = row['DefaultUserName']
            if "AutoAdminLogon" in header:
                auto_admin_logon = etree.SubElement(winlogon, "AutoAdminLogon")
                auto_admin_logon.text = row['AutoAdminLogon']
            if "ForceAutoLogon" in header:
                force_auto_logon = etree.SubElement(winlogon, "ForceAutoLogon")
                force_auto_logon.text = row['ForceAutoLogon']
            if "DefaultPassword" in header:
                def_pw = etree.SubElement(winlogon, "DefaultPassword")
                def_pw.text = row['DefaultPassword']
            if "DefaultDomain" in header:
                domain = etree.SubElement(winlogon, "DefaultDomain")
                domain.text = row['DefaultDomain']


def add_routes(host: etree.Element, entry: os.DirEntry):
    with open(entry.path, mode='r') as csv_file:
        csv_file.__next__()  # skip first row, This should contain PowerShell type information
        reader = csv.DictReader(csv_file)
        header = reader.fieldnames
        routes = etree.SubElement(host, "Routes")
        for row in reader:
            route = etree.SubElement(routes, "Route")
            if "AddressFamily" in header:
                af = etree.SubElement(route, "AddressFamily")
                af.text = row['AddressFamily']
            if "DestinationPrefix" in header:
                prefix = etree.SubElement(route, "DestinationPrefix")
                prefix.text = row['DestinationPrefix']
            if "InterfaceAlias" in header:
                if_alias = etree.SubElement(route, "InterfaceAlias")
                if_alias.text = row['InterfaceAlias']
            if "NextHop" in header:
                next_hop = etree.SubElement(route, "NextHop")
                next_hop.text = row['NextHop']
            if "RouteMetric" in header:
                metric = etree.SubElement(route, "RouteMetric")
                metric.text = row['RouteMetric']
            if "ifIndex" in header:
                if_index = etree.SubElement(route, "ifIndex")
                if_index.text = row['AddressFamily']
            if "InterfaceMetric" in header:
                if_metric = etree.SubElement(route, "InterfaceMetric")
                if_metric.text = row['InterfaceMetric']
            if "IsStatic" in header:
                is_static = etree.SubElement(route, "IsStatic")
                is_static.text = row['IsStatic']
            if "AdminDistance" in header:
                admin_distance = etree.SubElement(route, "AdminDistance")
                admin_distance.text = row['AdminDistance']


def add_shares(host: etree.Element, entry: os.DirEntry):
    try:
        with open(entry.path, mode='r') as csv_file:
            csv_file.__next__()  # skip first row, This should contain PowerShell type information
            reader = csv.DictReader(csv_file)
            header = reader.fieldnames
            shares = etree.SubElement(host, "Shares")
            share_acl_path = entry.path.replace("-shares.csv", "-share_acls.csv")
            share_acl_elements = {}
            try:
                with open(share_acl_path, "r") as share_acls:
                    share_acls.__next__()
                    sa_reader = csv.DictReader(share_acls)
                    sa_header = sa_reader.fieldnames
                    name = ""
                    for sa_row in sa_reader:
                        permission = etree.Element("Permission")
                        if "Name" in sa_header:
                            name = sa_row['Name']
                            permission.set("Name", sa_row['Name'])
                        if "ScopeName" in sa_header:
                            permission.set("ScopeName", sa_row['ScopeName'])
                        if "AccountName" in sa_header:
                            permission.set("AccountName", sa_row['AccountName'])
                        if "AccessControlType" in sa_header:
                            permission.set("AccessControlType", sa_row['AccessControlType'])
                        if "AccessRight" in sa_header:
                            permission.set("AccessRight", sa_row['AccessRight'])
                        if name in share_acl_elements:
                            share_acl_elements[name].append(permission)
                        else:
                            share_acl_elements[name] = [permission]
            except:
                pass
            share_ntfs_acls = entry.path.replace("-shares.csv", "-share_ntfs_acls.csv")
            share_ntfs_elements = {}
            try:
                with open(share_ntfs_acls, "r") as ntfs_acls:
                    ntfs_acls.__next__()
                    n_reader = csv.DictReader(ntfs_acls)
                    n_header = n_reader.fieldnames
                    name = ""
                    for n_row in n_reader:
                        permission = etree.Element("Permission")
                        if "Name" in n_header:
                            name = n_row['Name']
                            permission.set("Name", n_row['Name'])
                        if "AccountName" in n_header:
                            permission.set("AccountName", n_row['AccountName'])
                        if "AccessControlType" in n_header:
                            permission.set("AccessControlType", n_row['AccessControlType'])
                        if "AccessRight" in n_header:
                            permission.set("AccessRight", n_row['AccessRight'])
                        if name in share_ntfs_elements:
                            share_ntfs_elements[name].append(permission)
                        else:
                            share_ntfs_elements[name] = [permission]
            except:
                pass
            for row in reader:
                share = etree.SubElement(shares, "Share")
                if "Name" in header:
                    name = etree.SubElement(share, "Name")
                    name.text = row['Name']
                    if row['Name'] in share_acl_elements:
                        sp = etree.Element("SharePermissions")
                        for s in share_acl_elements[row['Name']]:
                            sp.append(s)
                        share.append(sp)
                    if row['Name'] in share_ntfs_elements:
                        np = etree.Element("NTFSPermissions")
                        for s in share_ntfs_elements[row['Name']]:
                            np.append(s)
                        share.append(np)
                if "Path" in header:
                    path = etree.SubElement(share, "Path")
                    path.text = row['Path']
                if "Description" in header:
                    desc = etree.SubElement(share, "Description")
                    desc.text = row['Description']
    except:
        pass


def add_file_path_checks(host: etree.Element, entry: os.DirEntry):
    with open(entry.path, mode='r') as csv_file:
        csv_file.__next__()  # skip first row, This should contain PowerShell type information
        reader = csv.DictReader(csv_file)
        header = reader.fieldnames
        path_checks = etree.SubElement(host, "PathACLChecks")
        path_acls_elements = {}
        for row in reader:
            acl = etree.Element("ACL")
            path_name = ""
            if "Path" in header:
                path_name = row['Path']
                acl.set('Path', row['Path'])
            if "AccountName" in header:
                acl.set('AccountName', row['AccountName'])
            if "AccessControlType" in header:
                acl.set('AccessControlType', row['AccessControlType'])
            if "AccessRight" in header:
                acl.set('AccessRight', row['AccessRight'])
            if path_name in path_acls_elements:
                path_acls_elements[path_name].append(acl)
            else:
                path_acls_elements[path_name] = [acl]
        for k in path_acls_elements:
            path_acl = etree.SubElement(path_checks, "PathACL")
            p = etree.SubElement(path_acl, "Path")
            p.text = k
            acls = etree.SubElement(path_acl, "ACLs")
            for i in path_acls_elements[k]:
                acls.append(i)


def add_defender(host: etree.Element, entry: os.DirEntry):
    with open(entry.path, mode='r') as csv_file:
        csv_file.__next__()  # skip first row, This should contain PowerShell type information
        reader = csv.DictReader(csv_file)
        header = reader.fieldnames
        defender = etree.SubElement(host, "Defender")
        for row in reader:
            for k in header:
                e = etree.SubElement(defender, k)
                e.text = row[k]

def main():
    parser = argparse.ArgumentParser(description="Tool to convert CSV files produced by sysinfo-collector into a XML "
                                                 "file")
    parser.add_argument("FOLDER", metavar="CSV-FOLDER", type=str,
                        help="The CSV file produced by sysinfo-collector")
    args = parser.parse_args()
    folder = args.FOLDER
    print (folder)

    if not os.path.isdir(folder):
        print("[-] Folder doesn't exist.")
        return

    sysinfo = etree.Element('SystemInfoCollector')
    host = etree.SubElement(sysinfo, "Host")

    # Make a new document tree
    doc = etree.ElementTree(sysinfo)

    with os.scandir(folder) as entries:
        for entry in entries:
            if entry.name.endswith("-hostinfo.csv"):
                add_hostinfo(host, entry)
            if entry.name.endswith("-bios.csv"):
                add_bios(host, entry)
            if entry.name.endswith("-config-checks.csv"):
                add_config_checks(host, entry)
            if entry.name.endswith("-hotfixes.csv"):
                add_hotfixes(host, entry)
            if entry.name.endswith("-netadapter.csv"):
                add_netadapter(host, entry)
            if entry.name.endswith("-netipaddresses.csv"):
                add_netips(host, entry)
            if entry.name.endswith("-services.csv"):
                add_services(host, entry)
            if entry.name.endswith("-users.csv"):
                add_users(host, entry)
            if entry.name.endswith("-groups.csv"):
                add_groups(host, entry)
            if entry.name.endswith("-fwprofiles.csv"):
                add_fw_profiles(host, entry)
            if entry.name.endswith("-ntp.csv"):
                add_ntp(host, entry)
            if entry.name.endswith("-smb_settings.csv"):
                add_smb(host, entry)
            if entry.name.endswith("-wsus.csv"):
                add_wsus(host, entry)
            if entry.name.endswith("-printer.csv"):
                add_printers(host, entry)
            if entry.name.endswith("-products.csv"):
                add_products(host, entry)
            if entry.name.endswith("-winlogon.csv"):
                add_winlogon(host, entry)
            if entry.name.endswith("-routes.csv"):
                add_routes(host, entry)
            if entry.name.endswith("-shares.csv"):
                add_shares(host, entry)
            if entry.name.endswith("-file_path_checks.csv"):
                add_file_path_checks(host, entry)
            if entry.name.endswith("-defender.csv"):
                add_defender(host, entry)
            # fileexistchecks

    # Save to XML file
    doc.write('output.xml', pretty_print=True, xml_declaration=True, encoding='utf-8')


if __name__=="__main__":
    main()