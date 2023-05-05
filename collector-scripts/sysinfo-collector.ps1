<# 
    .SYNOPSIS
    This PowerShell script is to fetch system information.

    .DESCRIPTION
    This PowerShell script is to fetch system information. The collector script is published as part of "systemdb".
    https://bitbucket.org/cbless/systemdb

    Author: Christoph Bless (bitbucket@cbless.de)

    .INPUTS
    None
    
    .OUTPUTS
    This script will create a XML-file with the collected system information. 
    
    .EXAMPLE
    .\sysinfo-collector.ps1  

#>
$date = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME

$path = Get-Location

$xmlfile = $path.Path + "\" + $date + "_" + $hostname + ".xml"

$settings =  New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.IndentChars = $(" "*4)

$xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
$xmlWriter.WriteStartDocument()


$xmlWriter.WriteStartElement("SystemInfoCollector")
    $xmlWriter.WriteAttributeString("version", "0.1")
    
    $xmlWriter.WriteStartElement("Host")

        $xmlWriter.WriteAttributeString("type", "Windows")
        
        # Adding Hostname to XML
        $xmlWriter.WriteElementString("Hostname", $hostname)

        # Get Systeminformation
        Write-Host "[*] Collecting general computer infos."
        $compInfo = Get-ComputerInfo

        #######################################################################
        # writing basic system information
        #######################################################################
        $xmlWriter.WriteElementString("Domain",[string] $compInfo.CsDomain)
        $xmlWriter.WriteElementString("DomainRole",[string] $compInfo.CsDomainRole);
        $xmlWriter.WriteElementString("OSVersion",[string] $compInfo.OSVersion);
        $xmlWriter.WriteElementString("OSBuildNumber",[string] $compInfo.OSBuildNumber);
        $xmlWriter.WriteElementString("OSName", [string] $compInfo.OSName);
        $xmlWriter.WriteElementString("OSInstallDate",[string] $compInfo.OSInstallDate);
        $xmlWriter.WriteElementString("OSProductType",[string] $compInfo.OSProductType);
        $xmlWriter.WriteElementString("LogonServer", [string] $compInfo.LogonServer);
        $xmlWriter.WriteElementString("TimeZone",[string]$compInfo.TimeZone);
        $xmlWriter.WriteElementString("KeyboardLayout",[string]$compInfo.KeyboardLayout);
        $xmlWriter.WriteElementString("HyperVisorPresent",[string]$compInfo.HyperVisorPresent);
        $xmlWriter.WriteElementString("DeviceGuardSmartStatus",[string]$compInfo.DeviceGuardSmartStatus);
        $xmlWriter.WriteElementString("PSVersion",[string]$PSVersionTable.PSVersion);

        #######################################################################
        # Collecting information about installed hotfixes / patches
        #######################################################################
        
        Write-Host "[*] Collecting installed hotfixes"
        $hotfixes = Get-HotFix
        
        $xmlWriter.WriteStartElement("Hotfixes")
        foreach ($h in $hotfixes ) {
            $xmlWriter.WriteStartElement("Hotfix")
            $xmlWriter.WriteAttributeString("id",  [string] $h.HotFixID);
            $xmlWriter.WriteAttributeString("InstalledOn",[string] $h.InstalledOn);
            $xmlWriter.WriteAttributeString("Description",[string] $h.Description);
            $xmlWriter.WriteEndElement() # hotfix
        }
        $xmlWriter.WriteEndElement() # hotfixes


        #######################################################################
        # Collecting information about installed products / applications
        #######################################################################
    
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

        
        #######################################################################
        # Collecting information about network adapters
        #######################################################################
        
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

        
        #######################################################################
        # Collecting information about ip addresses
        #######################################################################
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

        #######################################################################
        # Collecting information about services
        #######################################################################
    
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
            $xmlWriter.WriteElementString("Running",[string]$s.Running);
            $xmlWriter.WriteElementString("AcceptStop",[string]$s.AcceptStop);
            $xmlWriter.WriteElementString("AcceptPause",[string]$s.AcceptPause);
            $xmlWriter.WriteElementString("ProcessId",[string]$s.ProcessId);
            $xmlWriter.WriteElementString("DelayedAutoStart",[string]$s.DelayedAutoStart);
            try {
                $acl = get-acl -Path $s.PathName -ErrorAction SilentlyContinue
                $xmlWriter.WriteElementString("BinaryPermissions", [string] $acl.AccessToString)
            } catch {}
            $xmlWriter.WriteEndElement() # service
        }
        $xmlWriter.WriteEndElement() # services

        #######################################################################
        # Collecting information about local user accounts
        #######################################################################
    
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
            $xmlWriter.WriteElementString("PasswordChanged",[string]$u.PasswordChanged);
            $xmlWriter.WriteElementString("PasswordRequired",[string]$u.PasswordRequired);
            $xmlWriter.WriteEndElement() # user
        }
        $xmlWriter.WriteEndElement() # users



        #######################################################################
        # Collecting information about local groups
        #######################################################################
    
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


        #######################################################################
        # Collecting information about shares on the system
        #######################################################################
    
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
                $xmlWriter.WriteElementString("NTFSPermission", [string] $acl.AccessToString)
            } catch {}

            $share = "\\" + $hostname  +"\"+  [string]$s.Name
            try {
                $acl = get-acl -Path $share -ErrorAction SilentlyContinue
                $xmlWriter.WriteElementString("SharePermission", [string] $acl.AccessToString)
            } catch {}

            $xmlWriter.WriteEndElement() # share
        }
        $xmlWriter.WriteEndElement() # shares

        Write-Host "[*] Checking autologon configuration"           
        $xmlWriter.WriteStartElement("Winlogon")
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultUserName") {
            $user =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("DefaultUserName", $user.DefaultUserName)    
        } 
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultPassword") {
            $user =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("DefaultPassword", $user.DefaultPassword)    
        } 
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "AutoAdminLogon") {
            $user =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("AutoAdminLogon", $user.AutoAdminLogon)    
        } 
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "ForceAutoLogon") {
            $user =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ForceAutoLogon -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("ForceAutoLogon", $user.ForceAutoLogon)    
        } 
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultDomain") {
            $user =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomain -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("DefaultDomain", $user.DefaultDomain)   
        }
        $xmlWriter.WriteEndElement() # Winlogon

    $xmlWriter.WriteEndElement() # host
$xmlWriter.WriteEndElement() # SystemInfoCollector
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()
