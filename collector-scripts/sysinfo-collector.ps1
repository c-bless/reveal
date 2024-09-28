﻿<# 
    .SYNOPSIS
    This PowerShell script is to fetch system information.

    .DESCRIPTION
    This PowerShell script is to fetch system information. The collector script is published as part of "REVEAL".
    https://github.com/c-bless/reveal

    Author:     Christoph Bless (github@cbless.de)
    Version:    0.5
    License:    GPLv3

    .INPUTS
    None

    .OUTPUTS
    This script will create a XML-file with the collected system information.

    .EXAMPLE
    .\sysinfo-collector.ps1

    .Example
    .\sysinfo-collector.ps1 -Systemgroup PCS7 -Location "Control room" -Label "Inventory Number"
#>
param (
    # optional parameter to specify the systemgroup the host belongs to
    [Parameter(Mandatory=$false)]
    [string]$Systemgroup = "N/A",

    # name of the location
    [Parameter(Mandatory=$false)]
    [string]$Location = "N/A",

    # option for additional label
    [Parameter(Mandatory=$false)]
    [string]$Label = "N/A"
)


# version number of this script used as attribute in XML root tag
$version="0.5"


$date = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME

# can be generated with helper script ./genkey.py
$encKey = (7, 16, 166, 10, 141, 23, 37, 94, 240, 162, 206, 168, 181, 97, 19, 170)

$path = Get-Location

$xmlfile = $path.Path + "\" + $date + "_SystemInfoCollector_"+$version+"_" + $hostname + ".xml"

$settings =  New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.IndentChars = $(" "*4)

$xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
$xmlWriter.WriteStartDocument()

# ArrayList to store results from configuration checks. Those will be added as ConfigCheck-Tags at the end of the
# XML file between a ConfigChecks-Tag. All Custom objects that are added should follow the following structure
# $result = [PSCustomObject]@{
#     Component = 'AFFECT COMPONENT'
#     Name = 'NAME'
#     Method       = 'Registry'
#     Key   = 'KEY'
#     Value      = 'VALUE'
#     Result = 'RESULT'
#     Message = 'MESSAGE'
# }
$config_checks = New-Object System.Collections.ArrayList

$xmlWriter.WriteStartElement("SystemInfoCollector")
    $xmlWriter.WriteAttributeString("version", "$version")

    $xmlWriter.WriteStartElement("Host")

        $xmlWriter.WriteAttributeString("Type", "Windows")

        $xmlWriter.WriteElementString("SystemGroup", $Systemgroup)
        $xmlWriter.WriteElementString("Location", $Location)
        $xmlWriter.WriteElementString("Label", $Label)


        # Adding Hostname to XML
        $xmlWriter.WriteElementString("Hostname", $hostname)

        # Get Systeminformation
        Write-Host "[*] Collecting general computer infos."

        $xmlWriter.WriteElementString("OSBuildNumber",[string] [System.Environment]::OSVersion.Version.Build);


        ###############################################################################################################
        # Collecting basic information about the system
        # This includes OS Name, OS Version)
        ###############################################################################################################

        # if Get-ComputerInfo is available this command will be used to collect basic computer information.
        # This cmdlet was introduced in Windows PowerShell 5.1. Thus, for older versions a combination of WMI querries is used.
        if (Get-Command Get-ComputerInfo -ErrorAction SilentlyContinue){
            # we have at least PowerShell 5.1
            $compInfo = Get-ComputerInfo

            # writing basic system information
            $xmlWriter.WriteElementString("Domain",[string] $compInfo.CsDomain)
            $xmlWriter.WriteElementString("DomainRole",[string] $compInfo.CsDomainRole);

            if ([string]::IsNullOrEmpty($compInfo.OSVersion)){
                try{
                    $xmlWriter.WriteElementString("OSVersion",[string] $compInfo.WindowsVersion);
                }catch{}
            }else{
                $xmlWriter.WriteElementString("OSVersion",[string] $compInfo.OSVersion);
            }

            if ([string]::IsNullOrEmpty($compInfo.OSName)){
                try{
                    $xmlWriter.WriteElementString("OSName",[string] $compInfo.WindowsProductName);
                }catch{}
            }else{
                $xmlWriter.WriteElementString("OSName", [string] $compInfo.OSName);
            }

            $xmlWriter.WriteElementString("OSInstallDate",[string] $compInfo.OSInstallDate);
            $xmlWriter.WriteElementString("OSProductType",[string] $compInfo.OSProductType);
            $xmlWriter.WriteElementString("LogonServer", [string] $compInfo.LogonServer);
            $xmlWriter.WriteElementString("TimeZone",[string]$compInfo.TimeZone);
            $xmlWriter.WriteElementString("KeyboardLayout",[string]$compInfo.KeyboardLayout);
            $xmlWriter.WriteElementString("HyperVisorPresent",[string]$compInfo.HyperVisorPresent);
            $xmlWriter.WriteElementString("DeviceGuardSmartStatus",[string]$compInfo.DeviceGuardSmartStatus);
            $xmlWriter.WriteElementString("PrimaryOwnerName",[string] $compInfo.CSPrimaryOwnerName);

        }else{
            # No Get-ComputerInfo command. Thus, info must be collected using multiple technics
            $xmlWriter.WriteElementString("Domain",[string] [System.Environment]::UserDomainName);
            try{
                $cs = Get-WmiObject -Class win32_ComputerSystem -Property *
                $xmlWriter.WriteElementString("DomainRole",[string] $cs.DomainRole);
                $xmlWriter.WriteElementString("HyperVisorPresent",[string]$cs.HypervisorPresent);
                $xmlWriter.WriteElementString("OSInstallDate",[string] $cs.InstallDate);
                $xmlWriter.WriteElementString("Manufacturer",[string] $cs.CsManufacturer);
                $xmlWriter.WriteElementString("Model",[string] $cs.CsModel);
                $xmlWriter.WriteElementString("PrimaryOwnerName",[string] $cs.PrimaryOwnerName);
            } catch{}
            try{
                $os = Get-WmiObject Win32_OperatingSystem
                $xmlWriter.WriteElementString("OSVersion",[string] $os.Version);
                $xmlWriter.WriteElementString("OSName", [string] $os.Caption);
            } catch {
                $xmlWriter.WriteElementString("OSVersion",[string] [System.Environment]::OSVersion.Version);
                $xmlWriter.WriteElementString("OSName", [string] [System.Environment]::OSVersion.VersionString);
            }
            try {
                $timezone = Get-WmiObject -Class win32_timezone
                $xmlWriter.WriteElementString("TimeZone", $timezone.Caption);
            }catch{}
        }


        ###############################################################################################################
        # Collecting information about the current user
        ###############################################################################################################
        # user used to collect information
        $xmlWriter.WriteElementString("Whoami", [string] [System.Environment]::UserName);
        try {
            # check if user is admin
            $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
            $xmlWriter.WriteElementString("WhoamiIsAdmin", [string] $elevated);
        }catch{}


        ###############################################################################################################
        # Collecting information about active PowerShell version
        ###############################################################################################################
        $xmlWriter.WriteElementString("PSVersion",[string]$PSVersionTable.PSVersion);


        ###############################################################################################################
        # Collecting information about the BIOS
        ###############################################################################################################
        try{
            $xmlWriter.WriteStartElement("BIOS")
            $bios = Get-WmiObject -Class win32_bios
            $xmlWriter.WriteAttributeString("Manufacturer", [string] $bios.Manufacturer);
            $xmlWriter.WriteAttributeString("Name", [string] $bios.Name);
            $xmlWriter.WriteAttributeString("Version", [string] $bios.Version);
            $xmlWriter.WriteAttributeString("SerialNumber", [string] $bios.SerialNumber);
            $xmlWriter.WriteEndElement() # BIOS
        }catch{}


        ###############################################################################################################
        # Collecting information about installed hotfixes / patches
        ###############################################################################################################
        Write-Host "[*] Collecting installed hotfixes"
        $xmlWriter.WriteStartElement("Hotfixes")

        if (Get-Command Get-HotFix -ErrorAction SilentlyContinue){
            try{
                $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue
            } catch{
                $hotfixes = Get-HotFix
            }
            if ( $hotfixes.Length -gt 0 ){
                $lastUpdate = $hotfixes[0]
                $xmlWriter.WriteAttributeString("LastUpdate",  [string] $lastUpdate.InstalledOn);
            }else{
                $xmlWriter.WriteAttributeString("LastUpdate",  [string] "N/A");
            }

            foreach ($h in $hotfixes ) {
                $xmlWriter.WriteStartElement("Hotfix")
                $xmlWriter.WriteAttributeString("id",  [string] $h.HotFixID);
                $xmlWriter.WriteAttributeString("InstalledOn",[string] $h.InstalledOn);
                $xmlWriter.WriteAttributeString("Description",[string] $h.Description);
                $xmlWriter.WriteEndElement() # hotfix
            }
        } else {
            try{
                $hotfixes = Get-WmiObject -Class win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue
            } catch {
                $hotfixes = Get-WmiObject -Class win32_QuickFixEngineering
            }
            if ( $hotfixes.Length -gt 0 ){
                $lastUpdate = $hotfixes[0]
                $xmlWriter.WriteAttributeString("LastUpdate",  [string] $lastUpdate.InstalledOn);
            }else{
                $xmlWriter.WriteAttributeString("LastUpdate",  [string] "N/A");
            }

            foreach ($h in $hotfixes ) {
                $xmlWriter.WriteStartElement("Hotfix")
                $xmlWriter.WriteAttributeString("id",  [string] $h.HotFixID);
                $xmlWriter.WriteAttributeString("InstalledOn",[string] $h.InstalledOn);
                $xmlWriter.WriteAttributeString("Description",[string] $h.Description);
                $xmlWriter.WriteEndElement() # hotfix
            }
        }
        $xmlWriter.WriteEndElement() # hotfixes


        ###############################################################################################################
        # Collecting information about installed products / applications
        ###############################################################################################################

        Write-Host "[*] Collecting installed products"
        $products = Get-WmiObject  -class win32_product

        $xmlWriter.WriteStartElement("Products")
        foreach ($p in $products ) {
            $xmlWriter.WriteStartElement("Product")
            $xmlWriter.WriteElementString("Caption", [string] $p.Caption);
            $xmlWriter.WriteElementString("InstallDate", [string]$p.InstallDate);
            $xmlWriter.WriteElementString("Description",[string]$p.Description);
            $xmlWriter.WriteElementString("Vendor",[string]$p.Vendor);
            $xmlWriter.WriteElementString("Name",[string]$p.Name);
            $xmlWriter.WriteElementString("Version",[string]$p.Version);
            $xmlWriter.WriteElementString("InstallLocation",[string]$p.InstallLocation);
            $xmlWriter.WriteEndElement() # product
        }
        $xmlWriter.WriteEndElement() # products


        ###############################################################################################################
        # Collecting information about network adapters
        ###############################################################################################################

        if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
            Write-Host "[*] Collecting available network adapters"
            $netadapters = Get-NetAdapter

            $xmlWriter.WriteStartElement("Netadapters")
            foreach ($n in $netadapters ) {
                $xmlWriter.WriteStartElement("Netadapter")
                $xmlWriter.WriteAttributeString("MacAddress", [string] $n.MacAddress);
                $xmlWriter.WriteAttributeString("Status",[string] $n.Status);
                $xmlWriter.WriteAttributeString("Name",[string] $n.Name);
                $xmlWriter.WriteAttributeString("InterfaceDescription",[string] $n.InterfaceDescription);
                $xmlWriter.WriteEndElement() # netadapter
            }
            $xmlWriter.WriteEndElement() # netadapters
        }else{
            try{
                $netadapters = get-wmiobject -Class win32_networkadapter
                 foreach ($n in $netadapters ) {
                    $xmlWriter.WriteStartElement("Netadapter")
                    $xmlWriter.WriteAttributeString("MacAddress", [string] $n.MACAddress);
                    $xmlWriter.WriteAttributeString("Status",[string] $n.Status);
                    $xmlWriter.WriteAttributeString("Name",[string] $n.Name);
                    $xmlWriter.WriteAttributeString("Type",[string] $n.AdapterType);
                    $xmlWriter.WriteAttributeString("InterfaceDescription",[string] $n.Description);
                    $xmlWriter.WriteEndElement() # netadapter
                }
            }catch{}
        }

        ###############################################################################################################
        # Collecting information about ip addresses
        ###############################################################################################################

        if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue ) {
            Write-Host "[*] Collecting IP addresses"
            $netips = Get-NetIPAddress

            $xmlWriter.WriteStartElement("NetIPAddresses")
            foreach ($n in $netips ) {
                $xmlWriter.WriteStartElement("NetIPAddress")
                $xmlWriter.WriteAttributeString("AddressFamily", [string] $n.AddressFamily);
                $xmlWriter.WriteAttributeString("Type", [string] $n.Type);
                $xmlWriter.WriteAttributeString("IP", [string] $n.IPAddress);
                $xmlWriter.WriteAttributeString("Prefix", [string] $n.PrefixLength);
                $xmlWriter.WriteAttributeString("InterfaceAlias", [string] $n.InterfaceAlias);

                $xmlWriter.WriteEndElement() # NetIPAddress
            }
            $xmlWriter.WriteEndElement() # NetIPAddress
        } else {
            try{
                $netadapters = get-wmiobject -Class win32_networkadapterconfiguration -Filter "IPEnabled = 'True'"
                $xmlWriter.WriteStartElement("NetIPAddresses")
                 foreach ($n in $netadapters ) {
                    foreach ($i in $n.IPAddress){
                        $xmlWriter.WriteStartElement("NetIPAddress")
                        $xmlWriter.WriteAttributeString("IP",[string] $i);
                        $xmlWriter.WriteAttributeString("InterfaceAlias",[string] $n.Caption);
                        $xmlWriter.WriteAttributeString("DHCP",[string] $n.DHCPEnabled);
                        $xmlWriter.WriteEndElement() # netadapter
                    }
                }
                $xmlWriter.WriteEndElement() # NetIPAddress
            }catch{}
        }


        ###############################################################################################################
        # Collecting information about available routes (routing table)
        ###############################################################################################################
        Write-Host "[*] Collecting routing table"

        if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
            try{
                $routes = Get-NetRoute
                $xmlWriter.WriteStartElement("Routes")
                foreach ($r in $routes ) {
                    try{
                        $xmlWriter.WriteStartElement("Route")
                        $xmlWriter.WriteElementString("AddressFamily", [string] $r.AddressFamily);
                        $xmlWriter.WriteElementString("DestinationPrefix", [string]$r.DestinationPrefix);
                        $xmlWriter.WriteElementString("InterfaceAlias", [string]$r.InterfaceAlias);
                        $xmlWriter.WriteElementString("NextHop", [string]$r.NextHop);
                        $xmlWriter.WriteElementString("RouteMetric", [string]$r.RouteMetric);
                        $xmlWriter.WriteElementString("ifIndex", [string]$r.ifIndex);
                        $xmlWriter.WriteElementString("InterfaceMetric", [string]$r.InterfaceMetric);
                        $xmlWriter.WriteElementString("IsStatic", [string]$r.IsStatic);
                        $xmlWriter.WriteElementString("AdminDistance", [string]$r.AdminDistance);
                        $xmlWriter.WriteEndElement() # Route
                    }catch{}
                }
                $xmlWriter.WriteEndElement() # Routes
            }catch{}
        }


        ###############################################################################################################
        # Collecting information about services
        ###############################################################################################################

        Write-Host "[*] Collecting service information"
        $services = Get-WmiObject  -class win32_service

        $xmlWriter.WriteStartElement("Services")
        foreach ($s in $services ) {
            $xmlWriter.WriteStartElement("Service")
            $xmlWriter.WriteElementString("Caption", [string] $s.Caption);
            $xmlWriter.WriteElementString("Description",[string]$s.Description);
            $xmlWriter.WriteElementString("Name",[string]$s.Name);
            $xmlWriter.WriteElementString("StartMode",[string]$s.StartMode);
            $xmlWriter.WriteElementString("PathName", [string]$s.PathName);
            $xmlWriter.WriteElementString("Started",[string]$s.Started);
            $xmlWriter.WriteElementString("StartName",[string]$s.StartName);
            $xmlWriter.WriteElementString("SystemName",[string]$s.SystemName);
            $xmlWriter.WriteElementString("DisplayName",[string]$s.DisplayName);
            #$xmlWriter.WriteElementString("Running",[string]$s.Running);
            $xmlWriter.WriteElementString("AcceptStop",[string]$s.AcceptStop);
            $xmlWriter.WriteElementString("AcceptPause",[string]$s.AcceptPause);
            $xmlWriter.WriteElementString("ProcessId",[string]$s.ProcessId);
            $xmlWriter.WriteElementString("DelayedAutoStart",[string]$s.DelayedAutoStart);
            try {
                # check permissions of binary. Therefore parameters needed to be stripped from path, otherwise
                # Get-ACL will not work.
                $folder = Split-Path -Path $s.PathName
                $leaf = Split-Path -Path $s.PathName -Leaf
                $space = $leaf.IndexOf(" ")
                if ($space -eq -1) {
                    $bin = $s.PathName
                }else{
                    $bin = $folder+"\"+$leaf.Substring(0,$space)
                }
                $xmlWriter.WriteElementString("Executable",[string]$bin);


                $space2 = $bin.IndexOf('"')
                if ($space2 -ne -1){
                    $bin =$bin.Replace('"','')
                }

                $acl = get-acl -Path $bin -ErrorAction SilentlyContinue
                #$xmlWriter.WriteElementString("NTFSPermission", [string] $acl.AccessToString)
                $xmlWriter.WriteStartElement("BinaryPermissions")
                foreach ($a in $acl.Access) {
                    try{
                        $xmlWriter.WriteStartElement("Permission")
                        $xmlWriter.WriteAttributeString("Name", [string] $s.Name);
                        $xmlWriter.WriteAttributeString("AccountName", [string] $a.IdentityReference);
                        $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType);
                        $xmlWriter.WriteAttributeString("AccessRight", [string] $a.FileSystemRights);
                        $xmlWriter.WriteEndElement() # Permission
                    }catch{}
                }
                $xmlWriter.WriteEndElement() # BinaryPermissions

            } catch {}
            $xmlWriter.WriteEndElement() # service
        }
        $xmlWriter.WriteEndElement() # services


        ###############################################################################################################
        # Collecting information about local user accounts
        ###############################################################################################################

        # using WMI to be compatible with older PS versions
        Write-Host "[*] Collecting local user accounts"
        $users = Get-WmiObject -class win32_useraccount -Filter "LocalAccount=True"

        $xmlWriter.WriteStartElement("Users")
        foreach ($u in $users ) {
            $xmlWriter.WriteStartElement("User")
            $xmlWriter.WriteElementString("AccountType", [string] $u.AccountType);
            $xmlWriter.WriteElementString("Domain", [string]$u.Domain);
            $xmlWriter.WriteElementString("Disabled",[string]$u.Disabled);
            $xmlWriter.WriteElementString("LocalAccount",[string]$u.LocalAccount);
            $xmlWriter.WriteElementString("Name",[string]$u.Name);
            $xmlWriter.WriteElementString("FullName",[string]$u.FullName);
            $xmlWriter.WriteElementString("Description",[string]$u.Description);
            $xmlWriter.WriteElementString("SID",[string]$u.SID);
            $xmlWriter.WriteElementString("Lockout",[string]$u.Lockout);
            $xmlWriter.WriteElementString("PasswordChangeable",[string]$u.PasswordChangeable);
            $xmlWriter.WriteElementString("PasswordExpires",[string]$u.PasswordExpires);
            $xmlWriter.WriteElementString("PasswordRequired",[string]$u.PasswordRequired);
            $xmlWriter.WriteEndElement() # user
        }
        $xmlWriter.WriteEndElement() # users



        ###############################################################################################################
        # Collecting information about local groups
        ###############################################################################################################

        Write-Host "[*] Collecting local groups"
        $groups = Get-WmiObject -class win32_group -Filter "LocalAccount=True"

        $xmlWriter.WriteStartElement("Groups")
        foreach ($g in $groups ) {
            $xmlWriter.WriteStartElement("Group")
                $xmlWriter.WriteElementString("Name",[string]$g.Name);
                $xmlWriter.WriteElementString("Caption", [string] $g.Caption);
                $xmlWriter.WriteElementString("Description",[string]$g.Description);
                $xmlWriter.WriteElementString("LocalAccount",[string]$g.LocalAccount);
                $xmlWriter.WriteElementString("SID",[string]$g.SID);
                $xmlWriter.WriteStartElement("Members")

                $groupname = [string] $g.Name
                Write-Host "[*] - Enumerating members of group: $groupname"
                $query="Associators of {Win32_Group.Domain='$hostname',Name='$groupname'} where Role=GroupComponent"
                $members = get-wmiobject -query $query -ComputerName $hostname
                foreach ($m in $members){
                    $xmlWriter.WriteStartElement("Member")
                    $xmlWriter.WriteElementString("AccountType", [string] $m.AccountType);
                    $xmlWriter.WriteElementString("Domain", [string] $m.Domain);
                    $xmlWriter.WriteElementString("Name", [string] $m.Name);
                    $xmlWriter.WriteElementString("SID", [string] $m.SID);
                    $xmlWriter.WriteElementString("Caption", [string] $m.Caption);
                    $xmlWriter.WriteEndElement()
                }
                $xmlWriter.WriteEndElement() #Members
            $xmlWriter.WriteEndElement() # group

        }
        $xmlWriter.WriteEndElement() # groups


        ###############################################################################################################
        # Collecting information about shares on the system
        ###############################################################################################################

        $shares = Get-WmiObject -class win32_share
        # $shares = Get-CimInstance -ClassName Win32_Share
        Write-Host "[*] Collecting information about shares"
        $xmlWriter.WriteStartElement("Shares")
        foreach ($s in $shares ) {
            $xmlWriter.WriteStartElement("Share")
            $xmlWriter.WriteElementString("Name",[string]$s.Name);
            $xmlWriter.WriteElementString("Path",[string]$s.Path);
            $xmlWriter.WriteElementString("Description",[string]$s.Description);

            ## Get ACLs (NTFS)
            $path = [string] $s.Path
            try {
                $acl = get-acl -Path $path -ErrorAction SilentlyContinue
                #$xmlWriter.WriteElementString("NTFSPermission", [string] $acl.AccessToString)
                $xmlWriter.WriteStartElement("NTFSPermissions")
                foreach ($a in $acl.Access) {
                    $xmlWriter.WriteStartElement("Permission")
                    $xmlWriter.WriteAttributeString("Name", [string] $s.Name);
                    $xmlWriter.WriteAttributeString("AccountName", [string] $a.IdentityReference);
                    $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType);
                    $xmlWriter.WriteAttributeString("AccessRight", [string] $a.FileSystemRights);
                    $xmlWriter.WriteEndElement() # Permission
                }
                $xmlWriter.WriteEndElement() # NTFSPermissions
            } catch {}
            $xmlWriter.WriteStartElement("SharePermissions")
            if (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue) {
                try {
                    $acl = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
                    foreach ($a in $acl) {
                        $xmlWriter.WriteStartElement("Permission")
                        $xmlWriter.WriteAttributeString("Name", [string] $a.Name);
                        $xmlWriter.WriteAttributeString("ScopeName", [string] $a.ScopeName);
                        $xmlWriter.WriteAttributeString("AccountName", [string] $a.AccountName);
                        $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType);
                        $xmlWriter.WriteAttributeString("AccessRight", [string] $a.AccessRight);
                        $xmlWriter.WriteEndElement() # Permission
                    }
                } catch {}
            }else{
                try {
                    $share = "\\" + $hostname  +"\"+  [string]$s.Name
                    $acl = get-acl -Path $share -ErrorAction SilentlyContinue
                    foreach ($a in $acl.Access) {
                        $xmlWriter.WriteStartElement("Permission")
                        $xmlWriter.WriteAttributeString("Name", [string] $s.Name);
                        $xmlWriter.WriteAttributeString("ScopeName", "");
                        $xmlWriter.WriteAttributeString("AccountName", [string] $a.IdentityReference);
                        $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType);
                        $xmlWriter.WriteAttributeString("AccessRight", [string] $a.FileSystemRights);
                        $xmlWriter.WriteEndElement() # Permission
                    }
                } catch {}
            }
            $xmlWriter.WriteEndElement() # SharePermissions

            $xmlWriter.WriteEndElement() # share
        }
        $xmlWriter.WriteEndElement() # shares


        ###############################################################################################################
        # Collecting WSUS Settings in Registry
        ###############################################################################################################
        # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd939844(v=ws.10)?redirectedfrom=MSDN

        Write-Host "[*] Checking WSUS configuration"
        $xmlWriter.WriteStartElement("WSUS")
        if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "AcceptTrustedPublisherCerts") {
            $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name AcceptTrustedPublisherCerts -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("AcceptTrustedPublisherCerts", $wsus.AcceptTrustedPublisherCerts)
        }
        if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "DisableWindowsUpdateAccess") {
            $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name DisableWindowsUpdateAccess -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("DisableWindowsUpdateAccess", $wsus.DisableWindowsUpdateAccess)
        }
        if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "ElevateNonAdmins") {
            $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name ElevateNonAdmins -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("ElevateNonAdmins", $wsus.ElevateNonAdmins)
        }
        if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "TargetGroup") {
            $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name TargetGroup -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("TargetGroup", $wsus.TargetGroup)
        }
        if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "TargetGroupEnabled") {
            $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name TargetGroupEnabled -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("TargetGroupEnabled", $wsus.TargetGroupEnabled)
        }
        if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "WUServer") {
            $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("WUServer", $wsus.WUServer)
        }
        if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "WUStatusServer") {
            $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name WUStatusServer -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("WUStatusServer", $wsus.WUStatusServer)
        }
        $xmlWriter.WriteEndElement() # WSUS

        ###############################################################################################################
        # Collecting firewall status
        ###############################################################################################################
        if (Get-Command Get-NetFirewallProfile -ea SilentlyContinue) {
            Write-Host "[*] Collecting local firewall state"
            $xmlWriter.WriteStartElement("NetFirewallProfiles");
            try{
                $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
                foreach ($p in $profiles) {
                    try{
                        $xmlWriter.WriteStartElement("FwProfile");
                        $xmlWriter.WriteAttributeString("Name", [string] $p.Name)
                        $xmlWriter.WriteAttributeString("Enabled", [string] $p.Enabled)
                        $xmlWriter.WriteEndElement(); # FwProfile
                        if (!$p.Enabled){
                            $result = [PSCustomObject]@{
                                Component = 'Firewall'
                                Name = 'FirewallEnabled'
                                Method       = 'Get-NetFirewallProfile'
                                Key   = $p.Name
                                Value      = $p.Enabled
                                Result = 'Firewall is not enabled for the profile'
                            }
                            $config_checks.Add($result)
                        }
                    }catch{
                        # Ignore this ADComputer object and try to parse the next. No Tag will be added for this one.
                    }
                }
            }catch{
                # Failed executions will be ignored and no ADComputer tags will be added under ADComputerList
            }
            $xmlWriter.WriteEndElement(); # NetFirewallProfiles
        }

        ###############################################################################################################
        # Collecting WinLogon Settings
        ###############################################################################################################

        Write-Host "[*] Checking autologon configuration"
        $xmlWriter.WriteStartElement("Winlogon")
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultUserName") {
            $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("DefaultUserName", $value.DefaultUserName)
        }
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultPassword") {
            $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue
            $base64 = $false
            $encrypted = $false
            try {
                $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
                $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
                $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $aesManaged.BlockSize = 128
                $aesManaged.KeySize = 256
                $aesManaged.Key = $encKey
                $plainBytes = [Text.Encoding]::UTF8.GetBytes($value.DefaultPassword)
                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedText = $encryptor.TransformFinalBlock($plainBytes,0,$plainBytes.Length)

                $encrypted = $true
                $base64 = $true
                [byte[]] $fullData = $aesManaged.IV + $encryptedText
                $aesManaged.Dispose()
                $defaultPassword = [Convert]::ToBase64String($fullData)
            } catch {
                # .NET library for Cryptography not available.
                $defaultPassword = [convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value.DefaultPassword))
                $base64 = $true
                $encrypted = $false
            }
            $xmlWriter.WriteStartElement("DefaultPassword")
                $xmlWriter.WriteAttributeString("base64", [string] $base64)
                $xmlWriter.WriteAttributeString("encrypted", [string] $encrypted)
                $xmlWriter.WriteString($defaultPassword)
            $xmlWriter.WriteEndElement()
            # add additional entry to config_checks
            $result = [PSCustomObject]@{
                Component = 'Winlogon'
                Name = 'WinlogonDefaultPassword'
                Method       = 'Registry'
                Key   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword'
                Value      = $defaultPassword
                Result = 'DefaultPassword set'
                Message = 'Password for autologon user stored in Registry'
            }
            [void]$config_checks.Add($result)
        }
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "AutoAdminLogon") {
            $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("AutoAdminLogon", $value.AutoAdminLogon)
        }
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "ForceAutoLogon") {
            $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ForceAutoLogon -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("ForceAutoLogon", $value.ForceAutoLogon)
        }
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultDomainName") {
            $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("DefaultDomain", $value.DefaultDomain)
        }
        $xmlWriter.WriteEndElement() # Winlogon


        ###############################################################################################################
        # Collecting information about Installed PS Versions / Check if Version 2 is enabled
        ###############################################################################################################

        Write-Host "[*] Checking installed PS versions"
        $xmlWriter.WriteStartElement("PSVersions")
        $v2installed = $false

        $ids = (1..5)
        foreach ( $id in $ids) {
            $entry =  Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\$id\PowerShellEngine -ErrorAction SilentlyContinue
            if ($entry) {
                $xmlWriter.WriteStartElement("PSVersion")
                $xmlWriter.WriteAttributeString("Version", $entry.PowerShellVersion)
                $xmlWriter.WriteAttributeString("PSCompatibleVersion",  $entry.PSCompatibleVersion)
                $xmlWriter.WriteAttributeString("PSPath", $entry.PSPath)
                $xmlWriter.WriteAttributeString("RuntimeVersion", $entry.RuntimeVersion)
                $xmlWriter.WriteAttributeString("ConsoleHostModuleName", $entry.ConsoleHostModuleName)
                $xmlWriter.WriteEndElement()
                # if version is = 2.0 add an additional entry to $config_checks
                if ($entry.PowerShellVersion -eq "2.0"){
                    $v2installed = $true
                    $result = [PSCustomObject]@{
                        Component = 'PS'
                        Name = 'PSv2Installed'
                        Method       = 'Registry'
                        Key   = 'HKLM:\SOFTWARE\Microsoft\PowerShell\'+$id+'\PowerShellEngine\PowerShellVersion'
                        Value      = $entry.PowerShellVersion
                        Result = 'Installed'
                        Message = 'PS Version 2.0 installed'
                    }
                    [void]$config_checks.Add($result)
                }
            }
        }
        $xmlWriter.WriteEndElement() # PSVersions

        $xmlWriter.WriteElementString("PSVersion2Installed", $v2installed)

        ###############################################################################################################
        # Collecting information about Windows Scripting Host
        ###############################################################################################################

        Write-Host "[*] Checking settings for Windows Scripting Host"

        $xmlWriter.WriteStartElement("WSH")

        #######################################################################
        $wsh_trust_policy =""
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "TrustPolicy") {
            $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name TrustPolicy -ErrorAction SilentlyContinue
            $wsh_trust_policy = [string] $wsh.TrustPolicy
        }else{
            $wsh_trust_policy = "N/A"
        }
        $xmlWriter.WriteElementString("TrustPolicy", $wsh_trust_policy)
        $result = [PSCustomObject]@{
            Component = 'WSH'
            Name = 'WSHTrustPolicy'
            Method       = 'Registry'
            Key   = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\TrustPolicy'
            Value      = $wsh_trust_policy
            Result = $wsh_trust_policy
            Message = "No trust policy defined"
        }
        [void]$config_checks.Add($result)
        #######################################################################

        $wsh_enabled=1
        $wsh_enabled_status="Enabled"
        $wsh_enabled_result=""
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "Enabled") {
            $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name Enabled -ErrorAction SilentlyContinue
            $wsh_enabled = $wsh.Enabled
            if ($wsh.Enabled -eq 0){
                $wsh_enabled_result="Disabled (Explicit)"
                $wsh_enabled_status =  "Disabled"
            }else{
                $wsh_enabled_result="Enabled (Explicit)"
            }
        }else{
            $wsh_enabled_result="Enabled (Default)"
            $wsh_enabled = "N/A"
        }
        $xmlWriter.WriteElementString("EnabledStatus", $wsh_enabled_status)
        $result = [PSCustomObject]@{
            Component = 'WSH'
            Name = 'WSHEnable'
            Method       = 'Registry'
            Key   = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled'
            Value      = [string] $wsh_enabled
            Result = $wsh_enabled_status
            Message = $wsh_enabled_result
        }
        [void]$config_checks.Add($result)
        #######################################################################

        $wsh_remote=1
        $wsh_remote_status="Enabled"
        $wsh_remote_result=""

        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "Remote") {
            $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name Remote -ErrorAction SilentlyContinue
            $wsh_remote = $wsh.Remote
            if ($wsh.Remote -eq 0){
                $wsh_remote_result="Disabled (Explicit)"
                $wsh_remote_status =  "Disabled"
            }else{
                $wsh_remote_result="Enabled (Explicit)"
            }
        }else{
            $wsh_remote_result="Enabled (Default)"
            $wsh_remote="N/A"
        }

        $xmlWriter.WriteElementString("RemoteStatus", $wsh_remote_status)

        $result = [PSCustomObject]@{
            Component = 'WSH'
            Name = 'WSHRemote'
            Method       = 'Registry'
            Key   = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\Remote'
            Value      = $wsh_remote
            Result = $wsh_remote_status
            Message = $wsh_remote_result
        }
        [void]$config_checks.Add($result)

        $xmlWriter.WriteEndElement()

        ###############################################################################################################
        # Check if LLMNR is enabled
        ###############################################################################################################
        Write-Host "[*] Checking if LLMNR is enabled"
        $llmnr_value = ""
        $llmnr_result = ""
        $llmnr_msg = ""
        if ((get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"  -ea SilentlyContinue).Property -contains "EnableMulticast") {
            $em =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -ErrorAction SilentlyContinue
            $llmnr_value = $em.EnableMulticast
            if ($em.EnableMulticast -eq 0){
                $llmnr_result = "Disabled"
                $llmnr_msg = "LLMNR is disabled"
            }else{
                $llmnr_result = "Enabled"
                $llmnr_msg = "LLMNR is Enabled (not recommended)"
            }
        }else {
            $llmnr_result = "Enabled (not configured)"
            $llmnr_msg = "LLMNR is Enabled (not recommended)"
        }

        $result = [PSCustomObject]@{
            Component = 'LLMNR'
            Name = 'LLMNR - Enabled'
            Method       = 'Registry'
            Key   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            Value      = $llmnr_value
            Result = $llmnr_result
            Message = $llmnr_msg
        }
        [void]$config_checks.Add($result)
        
        ###############################################################################################################
        # Check if SMB Signing is required
        # https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview
        ###############################################################################################################
        Write-Host "[*] Checking if SMB Signing is enabled"
        # check if "Microsoft network client: Digitally sign communications (always)" is required
        $client_sign_value = ""
        $client_sign_result = ""
        $client_sign_msg = ""
        if ((get-item "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  -ea SilentlyContinue).Property -contains "RequireSecuritySignature") {
            $client_sign =  Get-ItemProperty -Path  "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  -Name RequireSecuritySignature -ErrorAction SilentlyContinue
            $client_sign_value = $ce.RequireSecuritySignature
            #  Data Type: REG_DWORD Data: 0 (disable), 1 (enable)
            if ($client_sign_value -eq 0){
                $client_sign_result = "Disabled"
                $client_sign_msg = "Microsoft network client: Digitally sign communications (always) is not required"
            }else{
                $client_sign_result = "Enabled"
                $client_sign_msg = "Microsoft network client: Digitally sign communications (always) is required"
            }
        }

        $result = [PSCustomObject]@{
            Component = 'SMB'
            Name = 'Microsoft network client: Digitally sign communications (always)'
            Method       = 'Registry'
            Key   = 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters\RequireSecuritySignature'
            Value      = $client_sign_value
            Result = $client_sign_result
            Message = $client_sign_msg
        }
        [void]$config_checks.Add($result)

        # check if "Microsoft network server: Digitally sign communications (always)" is required
        $srv_sign_value = ""
        $srv_sign_result = ""
        $srv_sign_msg = ""
        if ((get-item "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"  -ea SilentlyContinue).Property -contains "RequireSecuritySignature") {
            $srv_sign =  Get-ItemProperty -Path  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"  -Name RequireSecuritySignature -ErrorAction SilentlyContinue
            $srv_sign_value = $ce.RequireSecuritySignature
            #  Data Type: REG_DWORD Data: 0 (disable), 1 (enable)
            if ($srv_sign_value -eq 0){
                $srv_sign_result = "Disabled"
                $srv_sign_msg = "Microsoft network server: Digitally sign communications (always) is not required"
            }else{
                $srv_sign_result = "Enabled"
                $srv_sign_msg = "Microsoft network server: Digitally sign communications (always) is required"
            }
        }

        $result = [PSCustomObject]@{
            Component = 'SMB'
            Name = 'Microsoft network server: Digitally sign communications (always)'
            Method       = 'Registry'
            Key   = 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
            Value      = $srv_sign_value
            Result = $srv_sign_result
            Message = $srv_sign_msg
        }
        [void]$config_checks.Add($result)

        ###############################################################################################################
        # Collecting information about NTP settings
        ###############################################################################################################
        # https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings?tabs=config
        Write-Host "[*] Checking NTP configuration"
        
        $xmlWriter.WriteStartElement("NTP")
        if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "NtpServer") {
            $ntpServer =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name NtpServer -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("Server", [string] $ntpServer.NtpServer)
        }
        if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "Type") {
            $ntpType =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name Type -ErrorAction SilentlyContinue
            # NT5DS - Used for domain-joined computers
            # NTP - Used for non-domain-joined computers
            $xmlWriter.WriteElementString("Type", [string] $ntpType.Type)
        }
        if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"  -ea SilentlyContinue).Property -contains "UpdateInterval") {
            $interval =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name UpdateInterval -ErrorAction SilentlyContinue
            # default is 30000 for domain-joined computers
            # default is 360000 for non-domain-joined computers
            $xmlWriter.WriteElementString("UpdateInterval", [string] $interval.UpdateInterval)
        }
        $xmlWriter.WriteEndElement() 

        ###############################################################################################################
        # Collecting information about PowerShell (PS Logging enabled ?)
        ###############################################################################################################
        
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
        Write-Host "[*] Checking PS Logging is enabled"
        
        if ((get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"  -ea SilentlyContinue).Property -contains "EnableScriptBlockLogging") {
            $logging =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
            if ($logging -eq 1){
                $xmlWriter.WriteElementString("PSScriptBlockLogging", "Enabled")
            }else{
                $xmlWriter.WriteElementString("PSScriptBlockLogging", "Disabled")
            }
        }

        
        ###############################################################################################################
        # Check SSL / TLS settings
        # https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings?tabs=diffie-hellman
        ###############################################################################################################
        
        Write-Host "[*] Checking SSL/TLS settings"
        
        $ssl_tls_versions = New-Object System.Collections.ArrayList
        [void]$ssl_tls_versions.add("SSL 2.0")
        [void]$ssl_tls_versions.add("SSL 3.0")
        [void]$ssl_tls_versions.add("TLS 1.0")
        [void]$ssl_tls_versions.add("TLS 1.1")
        [void]$ssl_tls_versions.add("TLS 1.2")
        [void]$ssl_tls_versions.add("DTLS 1.2")

        
        foreach ( $v in $ssl_tls_versions) {
          
            if ((get-item HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\Client  -ea SilentlyContinue).Property -contains "Enabled") {
                $version_enabled =  Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\Client -Name Enabled -ErrorAction SilentlyContinue
                if ($version_enabled.Enabled -eq 0){
                    $result = [PSCustomObject]@{
                        Component = 'SSL/TLS'
                        Name = $v + ' - disabled (Client)'
                        Method       = 'Registry'
                        Key   =  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$v+'\Client\Enabled'
                        Value      = $version_enabled.Enabled
                        Result = "Disabled (explicit)"
                        Message = $v + ' is disabled (Client)'
                    }
                    [void]$config_checks.Add($result)
                }else{
                    $result = [PSCustomObject]@{
                        Component = 'SSL/TLS'
                        Name = $v + ' - disabled (Client)'
                        Method       = 'Registry'
                        Key   =  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$v+'\Client\Enabled'
                        Value      = $version_enabled.Enabled
                        Result = "Enabled (explicit)"
                        Message = $v + ' is enabled (Client)'
                    }
                    [void]$config_checks.Add($result)
                }
            }else {
                $result = [PSCustomObject]@{
                    Component = 'SSL/TLS'
                    Name = $v + ' - disabled (Client)'
                    Method       = 'Registry'
                    Key   =  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$v+'\Client\Enabled'
                    Value      = $null
                    Result = "Not configured"
                    Message = $v + ' is not configured (Client)'
                }
                [void]$config_checks.Add($result)
            }

            if ((get-item HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\Server  -ea SilentlyContinue).Property -contains "Enabled") {
                $version_enabled =  Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\Server -Name Enabled -ErrorAction SilentlyContinue
                if ($version_enabled.Enabled -eq 0){
                    $result = [PSCustomObject]@{
                        Component = 'SSL/TLS'
                        Name = $v + ' - disabled  (Server)'
                        Method       = 'Registry'
                        Key   =  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$v+'\Server\Enabled'
                        Value      = $version_enabled.Enabled
                        Result = "Disabled (explicit)"
                        Message = $v + ' is disabled (Server)'
                    }
                    [void]$config_checks.Add($result)
                }else{
                    $result = [PSCustomObject]@{
                        Component = 'SSL/TLS'
                        Name = $v + ' - disabled (Server)'
                        Method       = 'Registry'
                        Key   =  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$v+'\Server\Enabled'
                        Value      = $version_enabled.Enabled
                        Result = "Enabled (explicit)"
                        Message = $v + ' is enabled (Server)'
                    }
                    [void]$config_checks.Add($result)
                }
            }else {
                $result = [PSCustomObject]@{
                    Component = 'SSL/TLS'
                    Name = $v + ' - disabled (Server)'
                    Method       = 'Registry'
                    Key   =  'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$v+'\Server\Enabled'
                    Value      = $null
                    Result = "Not configured"
                    Message = $v + ' is not configured (Server)'
                }
                [void]$config_checks.Add($result)
            }
        }

       
        
        ###############################################################################################################
        # Collecting information about SMB (Check if SMBv1 is enabled)
        ###############################################################################################################
        
        # https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server
        Write-Host "[*] Checking if SMBv1 is enabled"
        
        $xmlWriter.WriteStartElement("SMBSettings")
        
        $smb_method=""
        
        if (Get-Command Get-SmbServerConfiguration -ea SilentlyContinue) {
            # Cmdlet has been introduced in Windows 8, Windows Server 2012
            $smb_method= "Get-SmbServerConfiguration"
            $smb = Get-SmbServerConfiguration 
            $xmlWriter.WriteElementString("SMB1Enabled", [string] $smb.EnableSMB1Protocol)
            $xmlWriter.WriteElementString("SMB2Enabled", [string] $smb.EnableSMB2Protocol)
            $xmlWriter.WriteElementString("EncryptData", [string] $smb.EncryptData)
            $xmlWriter.WriteElementString("EnableSecuritySignature", [string] $smb.EnableSecuritySignature)
            $xmlWriter.WriteElementString("RequireSecuritySignature", [string] $smb.RequireSecuritySignature)
            
        } else {
            $smb_method= "Registry"
            # older Windows versions can check the registry.
            if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "SMB1") {
                $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue
                if ($smb1 -eq 0){ 
                    $xmlWriter.WriteElementString("SMB1Enabled", "False")
                } else{
                    $xmlWriter.WriteElementString("SMB1Enabled", "True")   
                    
                }
            } else {
                # Enabled by default. Since the entry does not exist it is enabled
                $xmlWriter.WriteElementString("SMB1Enabled", "True")  
            }

            if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "SMB2") {
                $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -ErrorAction SilentlyContinue
                if ($smb1 -eq 0){
                    $xmlWriter.WriteElementString("SMB2Enabled", "False")  
                } else{
                    $xmlWriter.WriteElementString("SMB2Enabled", "True")  
                    
                }
            } else {
                # Enabled by default. Since the entry does not exist it is enabled
                $xmlWriter.WriteElementString("SMB2Enabled", "True")  
            }

            if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "EnableSecuritySignature") {
                $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name EnableSecuritySignature -ErrorAction SilentlyContinue
                $xmlWriter.WriteElementString("EnableSecuritySignature", [string] $smb.EnableSecuritySignature)
            }
             
            if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "RequireSecuritySignature") {
                $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -ErrorAction SilentlyContinue
                $xmlWriter.WriteElementString("RequireSecuritySignature", [string] $smb.RequireSecuritySignature)
            }
        }
        

        $xmlWriter.WriteEndElement() 
        

        ###############################################################################################################
        # Collecting information about Defender (Status / Settings)
        ###############################################################################################################
        
        Write-Host "[*] Checking Defender settings"
        if (Get-Command Get-MpComputerStatus -ea SilentlyContinue) {
            $xmlWriter.WriteStartElement("DefenderStatus")
            $status = Get-MpComputerStatus
            $xmlWriter.WriteElementString("AMEngineVersion", [string] $status.AMEngineVersion)
            $xmlWriter.WriteElementString("AMProductVersion",  [string] $status.AMProductVersion)
            $xmlWriter.WriteElementString("AMServiceEnabled",  [string] $status.AMServiceEnabled)
            $xmlWriter.WriteElementString("AMServiceVersion",  [string] $status.AMServiceVersion)
            $xmlWriter.WriteElementString("AntispywareEnabled",  [string] $status.AntispywareEnabled)
            $xmlWriter.WriteElementString("AntispywareSignatureLastUpdated",  [string] $status.AntispywareSignatureLastUpdated)
            $xmlWriter.WriteElementString("AntispywareSignatureVersion",  [string] $status.AntispywareSignatureVersion)
            $xmlWriter.WriteElementString("AntivirusEnabled",  [string] $status.AntivirusEnabled)
            $xmlWriter.WriteElementString("AntivirusSignatureLastUpdated",  [string] $status.AntivirusSignatureLastUpdated)
            $xmlWriter.WriteElementString("AntivirusSignatureVersion",  [string] $status.AntivirusSignatureVersion)
            $xmlWriter.WriteElementString("BehaviorMonitorEnabled",  [string] $status.BehaviorMonitorEnabled)
            $xmlWriter.WriteElementString("IoavProtectionEnabled",  [string] $status.IoavProtectionEnabled)
            $xmlWriter.WriteElementString("IsVirtualMachine",  [string] $status.IsVirtualMachine)
            $xmlWriter.WriteElementString("NISEnabled",  [string] $status.NISEnabled)
            $xmlWriter.WriteElementString("NISEngineVersion",  [string] $status.NISEngineVersion)
            $xmlWriter.WriteElementString("NISSignatureLastUpdated",  [string] $status.NISSignatureLastUpdated)
            $xmlWriter.WriteElementString("NISSignatureVersion",  [string] $status.NISSignatureVersion)
            $xmlWriter.WriteElementString("OnAccessProtectionEnabled",  [string] $status.OnAccessProtectionEnabled)
            $xmlWriter.WriteElementString("RealTimeProtectionEnabled",  [string] $status.RealTimeProtectionEnabled)
            $xmlWriter.WriteEndElement() # Defender
        }
        if (Get-Command Get-MpPreference -ea SilentlyContinue) {
            $xmlWriter.WriteStartElement("Defender")
            $preferences = Get-MpPreference 
            $xmlWriter.WriteElementString("DisableArchiveScanning", [string] $preferences.DisableArchiveScanning) 
            $xmlWriter.WriteElementString("DisableAutoExclusions",  [string] $preferences.DisableAutoExclusions)
            $xmlWriter.WriteElementString("DisableBehaviorMonitoring", [string] $preferences.DisableBehaviorMonitoring)
            $xmlWriter.WriteElementString("DisableBlockAtFirstSeen",  [string] $preferences.DisableBlockAtFirstSeen)   
            $xmlWriter.WriteElementString("DisableCatchupFullScan",  [string] $preferences.DisableCatchupFullScan)   
            $xmlWriter.WriteElementString("DisableCatchupQuickScan",  [string] $preferences.DisableCatchupQuickScan)   
            $xmlWriter.WriteElementString("DisableEmailScanning",  [string] $preferences.DisableEmailScanning)   
            $xmlWriter.WriteElementString("DisableIntrusionPreventionSystem",  [string] $preferences.DisableIntrusionPreventionSystem)   
            $xmlWriter.WriteElementString("DisableIOAVProtection",  [string] $preferences.DisableIOAVProtection)   
            $xmlWriter.WriteElementString("DisableRealtimeMonitoring", [string] $preferences.DisableRealtimeMonitoring)
            $xmlWriter.WriteElementString("DisableRemovableDriveScanning",  [string] $preferences.DisableRemovableDriveScanning)   
            $xmlWriter.WriteElementString("DisableRestorePoint",  [string] $preferences.DisableRestorePoint)   
            $xmlWriter.WriteElementString("DisableScanningMappedNetworkDrivesForFullScan",  [string] $preferences.DisableScanningMappedNetworkDrivesForFullScan)   
            $xmlWriter.WriteElementString("DisableScanningNetworkFiles",  [string] $preferences.DisableScanningNetworkFiles)   
            $xmlWriter.WriteElementString("DisableScriptScanning",  [string] $preferences.DisableScriptScanning)        
            $xmlWriter.WriteElementString("EnableNetworkProtection",  [string] $preferences.EnableNetworkProtection)   
            $xmlWriter.WriteElementString("ExclusionPath",  [string] $preferences.ExclusionPath)   
            $xmlWriter.WriteElementString("ExclusionProcess",  [string] $preferences.ExclusionProcess)  
            $xmlWriter.WriteEndElement() # Defender
        }

        ###############################################################################################################
        # Collecting information about Printer
        ###############################################################################################################
        
        Write-Host "[*] Checking if printers are installed"
        if (Get-Command Get-Printer -ea SilentlyContinue) {
            try {
                $printers = Get-Printer -ea SilentlyContinue
                $xmlWriter.WriteStartElement("Printers")
                foreach ($p in $printers) {
                    $xmlWriter.WriteStartElement("Printer")
                    $xmlWriter.WriteElementString("Name", [string] $p.Name)
                    $xmlWriter.WriteElementString("ShareName", [string] $p.ShareName)
                    $xmlWriter.WriteElementString("Type", [string] $p.Type)
                    $xmlWriter.WriteElementString("DriverName", [string] $p.DriverName)
                    $xmlWriter.WriteElementString("PortName", [string] $p.PortName)
                    $xmlWriter.WriteElementString("Shared", [string] $p.Shared)
                    $xmlWriter.WriteElementString("Published", [string] $p.Published)
                    $xmlWriter.WriteEndElement() # Printer
                }
                $xmlWriter.WriteEndElement() # Printers
            }catch{}
        }
        
        
        ###############################################################################################################
        # Perform: File Existence Checks
        # This will check if specified files exist on the system and if they are matching a predefined hash. 
        # The matching of HASH is only performed in recent PowerShell versions by using Get-FileHash
        ###############################################################################################################
        
        Write-Host "[*] Checking for existence of specified files"
        # ArrayList to store results from file existence checks. Those will be added as FileExistence-Tags.
        # All Custom objects that are added should follow the following structure
        # $result = [PSCustomObject]@{
        #     Name = 'NAME of the check'
        #     File   = 'Pathname'
        #     ExpectedHASH  = 'HASH'
        # }
        $file_checks = New-Object System.Collections.ArrayList
        $file_checks_results = New-Object System.Collections.ArrayList

        # Template for file checks
        # generate expected hash via: Get-FileHash -Path C:\temp\testfile.txt -Algorithm SHA256

        #[void]$file_checks.Add(
        #    [PSCustomObject]@{
        #        Name = 'Testfile'
        #        File   =  'C:\temp\testfile.txt'
        #        ExpectedHASH  = 'D37B9395C2BAF168F977CE9FF9EC007D7270FC84CBF1549324BFC8DFC34333A9'
        #    }
        #)

        # [MODIFY ME: ADD ADDITIONAL FILES HERE]

        foreach ($c in $file_checks){
            $result = [PSCustomObject]@{
                Name = $c.Name
                File   = $c.File
                ExpectedHASH  = $c.ExpectedHASH
                FileExist = $false
                HashMatch = $false
                HashChecked = $false
                CurrentHash= ''
            }
            try{ 
                $path = [string] $c.File
                if (Test-Path $path){
                    write-host "[!] Found file: "$path
                    $result.FileExist = $true
                    if (Get-Command Get-FileHash -ErrorAction SilentlyContinue){
                        $expectedHash = [string] $c.ExpectedHASH
                        $hash = Get-FileHash -Path $path -Algorithm SHA256
                        if ($expectedHash -eq $hash.HASH){ 
                            $result.HashMatch = $true
                            $result.HashChecked = $true
                        } else{
                            $result.HashMatch = $false
                        }
                        $result.CurrentHash = $hash.Hash
                    }
                }else{
                    $result.FileExist = $false
                }
                [void]$file_checks_results.Add($result)
            } catch {}
        }


        # Perform: FileExistence Checks 
        
        $xmlWriter.WriteStartElement("FileExistChecks")
        foreach ($c in $file_checks_results){
            $xmlWriter.WriteStartElement("FileExistCheck")
            $xmlWriter.WriteElementString("Name",[string] $c.Name)
            $xmlWriter.WriteElementString("File", [string] $c.File)
            $xmlWriter.WriteElementString("ExpectedHASH", [string] $c.ExpectedHASH)
            $xmlWriter.WriteElementString("FileExist", [string] $c.FileExist)
            $xmlWriter.WriteElementString("HashMatch", [string] $c.HashMatch)
            $xmlWriter.WriteElementString("HashChecked", [string] $c.HashChecked)
            $xmlWriter.WriteElementString("CurrentHash", [string] $c.CurrentHash)
            $xmlWriter.WriteEndElement() # FileExistCheck
        }
        $xmlWriter.WriteEndElement() # FileExistChecks
    
        

        ###############################################################################################################
        # Perform: Path ACL Checks
        ###############################################################################################################
        
        Write-Host "[*] Checking ACLs for specified pathes"
        # ArrayList of pathes that should be checked 
        $acl_path_checks = New-Object System.Collections.ArrayList

        [void]$acl_path_checks.Add('C:\')
        [void]$acl_path_checks.Add('C:\Program Files\')
        [void]$acl_path_checks.Add('C:\Program Files (x86)\')

        # [MODIFY ME: ADD ADDITIONAL PATHES HERE]

        $xmlWriter.WriteStartElement("PathACLChecks")
        foreach ($c in $acl_path_checks){
            $path = [string] $c
            if (Test-Path $path){
                $acl = get-acl -Path $path -ErrorAction SilentlyContinue
                $xmlWriter.WriteStartElement("PathACL");
                $xmlWriter.WriteElementString("Path", [string] $path);
                $xmlWriter.WriteStartElement("ACLs")
                foreach ($a in $acl.Access) {
                    try{
                        $xmlWriter.WriteStartElement("ACL");
                        $xmlWriter.WriteAttributeString("path", [string] $path);
                        $xmlWriter.WriteAttributeString("AccountName", [string] $a.IdentityReference);
                        $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType);
                        $xmlWriter.WriteAttributeString("AccessRight", [string] $a.FileSystemRights);
                        $xmlWriter.WriteEndElement() # ACL
                    }catch{}
                }
                $xmlWriter.WriteEndElement() # ACLs
                $xmlWriter.WriteEndElement() # PathACL
            }
        }
        $xmlWriter.WriteEndElement() # PathACLChecks

       
        ###############################################################################################################
        # Perform: Additional checks for entries in Windows Registry
        #######################################################################
        Write-Host "[*] Checking additional entries in Windows Registry"
        $registry_checks = New-Object System.Collections.ArrayList  

        # Sticky Keys
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'Sticky Keys disabled'
                Description = 'Checks if Sticky Keys are disabled (Press SHIFT 5 times)'
                Path        = 'HKCU:\Control Panel\Accessibility\StickyKeys\'
                Key         = 'Flags'
                Expected    = '506'
            }
        )

        # Filter Keys
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'Filter Keys disabled'
                Description = 'Checks if Filter Keys are disabled (Hold right SHIFT for 12 seconds)'
                Path        = 'HKCU:\Control Panel\Accessibility\Keyboard Response\'
                Key         = 'Flags'
                Expected    = '122'
            }
        )

        # Toggle Keys
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'Toggle Keys disabled'
                Description = 'Checks if Toggle Keys are disabled (Hold NUMLOCK for 5 seconds)'
                Path        = 'HKCU:\Control Panel\Accessibility\ToggleKeys\'
                Key         = 'Flags'
                Expected    = '58'
            }
        )

        # Mouse Keys
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'Mouse Keys disabled'
                Description = 'Checks if Mouse Keys are disabled (SHIFT + ALT + NUMLOCK)'
                Path        = 'HKCU:\Control Panel\Accessibility\MouseKeys\'
                Key         = 'Flags'
                Expected    = '59'
            }
        )

        # Windows Key Disabled
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'Windows Key disabled'
                Description = 'Checks if Windows Keys are disabled.'
                Path        = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
                Key         = 'NoWinKeys'
                Expected    = 0x1
            }
        )

        # Access to CMD blocked
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'CMD Blocked'
                Description = 'Checks if access to CMD is blocked.'
                Path        = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System\'
                Key         = 'DisableCMD'
                Expected    = '2'
            }
        )

        # Access to Registry Tools blocked
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'Registry Tools Blocked'
                Description = 'Checks if access to Registry tools is blocked.'
                Path        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
                Key         = 'DisableRegistryTools'
                Expected    = '1'
            }
        )

        # Access to control panel blocked
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'Control Panel Blocked'
                Description = 'Checks if access to control panel is blocked.'
                Path        = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'
                Key         = 'NoControlPanel'
                Expected    = '1'
            }
        )

        # Access to TaskManager blocked
        [void]$registry_checks.Add(
            [PSCustomObject]@{
                Category    = 'Hardening'
                Tags        = 'HMI Hardening, CITRIX Hardening'
                Name        = 'TaskManager Blocked'
                Description = 'Checks if access to task manager is blocked.'
                Path        = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System\'
                Key         = 'DisableTaskMgr'
                Expected    = '1'
            }
        )

        # [MODIFY ME: ADD ADDITIONAL REGISTRY CHECKS HERE]
        
        # Perform the above specified Registry Checks
        
        $registry_check_results = New-Object System.Collections.ArrayList  
        foreach ($c in $registry_checks){
            $result = [PSCustomObject]@{
                Category    = $c.Category
                Tags        = $c.Tags
                Name        = $c.Name
                Description = $c.Description
                Path        = $c.Path
                Key         = $c.Key
                Expected    = $c.Expected
                KeyExists   = $false
                ValueMatch  = $false
                CurrentValue= ''
            }
            try{ 
                $path = [string] $c.Path
                if (Test-Path $path){
                    $key = [string] $c.Key
                    if ((get-item $path  -ea SilentlyContinue).Property -contains $key) {
                        $result.KeyExists = $true
                        $value = Get-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
                        $value = [string] ($value).$key
                        $expected = [string] $c.Expected
                        $result.CurrentValue = $value
                        # both are casted to string -> compare with -eq
                        if ($expected -eq $value){ 
                            $result.ValueMatch = $true
                        } else{
                            $result.ValueMatch = $false
                        }
                    } 
                }else{
                    $result.KeyExists = $false
                }
                [void]$registry_check_results.Add($result)
            } catch {}
        }
               
        # Add results to XML

        $xmlWriter.WriteStartElement("AdditionalRegistryChecks")
        foreach ($c in $registry_check_results){
            $xmlWriter.WriteStartElement("RegistryCheck")
            $xmlWriter.WriteAttributeString("Category",[string] $c.Category)
            $xmlWriter.WriteAttributeString("Name", [string] $c.Name)
            $xmlWriter.WriteElementString("Description", [string] $c.Description)
            try {
                $xmlWriter.WriteElementString("Tags", [string] $c.Tags)
            }catch{}
            $xmlWriter.WriteElementString("Path", [string] $c.Path)
            $xmlWriter.WriteElementString("Key", [string] $c.Key)
            $xmlWriter.WriteElementString("Expected", [string] $c.Expected)
            $xmlWriter.WriteElementString("KeyExists", [string] $c.KeyExists)
            $xmlWriter.WriteElementString("ValueMatch", [string] $c.ValueMatch)
            $xmlWriter.WriteElementString("CurrentValue", [string] $c.CurrentValue)
            $xmlWriter.WriteEndElement() # RegistryCheck
        }
        $xmlWriter.WriteEndElement() # AdditionalRegistryChecks

        ###############################################################################################################
        # Adding ConfigChecks to xml. 
        # This in done at the end of the document, cause checks can be added from each performed check in the script. 
        ###############################################################################################################
        
        $xmlWriter.WriteStartElement("ConfigChecks")
        foreach ($c in $config_checks){
            $xmlWriter.WriteStartElement("ConfigCheck")
            $xmlWriter.WriteAttributeString("Component",[string] $c.Component)
            $xmlWriter.WriteAttributeString("Name", [string] $c.Name)
            $xmlWriter.WriteAttributeString("Method", [string] $c.Method)
            $xmlWriter.WriteElementString("Key", [string] $c.Key)
            $xmlWriter.WriteElementString("Value", [string] $c.Value)
            $xmlWriter.WriteElementString("Result", [string] $c.Result)
            $xmlWriter.WriteElementString("Message", [string] $c.Message)
            $xmlWriter.WriteEndElement()
        }
        $xmlWriter.WriteEndElement() # ConfigChecks


    $xmlWriter.WriteEndElement() # host
$xmlWriter.WriteEndElement() # SystemInfoCollector
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()
