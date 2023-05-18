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

# version number of this script used as attribute in XML root tag 
$version="0.1"


$date = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME

$path = Get-Location

$xmlfile = $path.Path + "\" + $date + "_SystemInfoCollector_"+$version+"_" + $hostname + ".xml"

$settings =  New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.IndentChars = $(" "*4)

$xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
$xmlWriter.WriteStartDocument()



$xmlWriter.WriteStartElement("SystemInfoCollector")
    $xmlWriter.WriteAttributeString("version", "$script_version")
    
    $xmlWriter.WriteStartElement("Host")

        $xmlWriter.WriteAttributeString("type", "Windows")
        
        # Adding Hostname to XML
        $xmlWriter.WriteElementString("Hostname", $hostname)

        # Get Systeminformation
        Write-Host "[*] Collecting general computer infos."
        
        if (Get-Command Get-ComputerInfo -ErrorAction SilentlyContinue){
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
            $xmlWriter.WriteElementString("PrimaryOwnerName",[string] $compInfo.CSPrimaryOwnerName);

        }else{
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
                $xmlWriter.WriteElementString("OSBuildNumber",[string] $os.BuildNumber);
                $xmlWriter.WriteElementString("OSName", [string] $os.Caption);
            } catch {
                $xmlWriter.WriteElementString("OSVersion",[string] [System.Environment]::OSVersion.Version);
                $xmlWriter.WriteElementString("OSBuildNumber",[string] [System.Environment]::OSVersion.Version.Build);
                $xmlWriter.WriteElementString("OSName", [string] [System.Environment]::OSVersion.VersionString);
            }
            try {
                $timezone = Get-WmiObject -Class win32_timezone
                $xmlWriter.WriteElementString("TimeZone", $timezone.Caption);
            }catch{}

        }

        $xmlWriter.WriteElementString("Whoami", [string] [System.Environment]::UserName);
        $xmlWriter.WriteElementString("PSVersion",[string]$PSVersionTable.PSVersion);
        try{
            $xmlWriter.WriteStartElement("BIOS")
            $bios = Get-WmiObject -Class win32_bios
            $xmlWriter.WriteAttributeString("Manufacturer", [string] $bios.Manufacturer);
            $xmlWriter.WriteAttributeString("Name", [string] $bios.Name);
            $xmlWriter.WriteAttributeString("Version", [string] $bios.Version);
            $xmlWriter.WriteAttributeString("SerialNumber", [string] $bios.SerialNumber);
            $xmlWriter.WriteEndElement() # BIOS
        }catch{}

        #######################################################################
        # Collecting information about installed hotfixes / patches
        #######################################################################
        
        Write-Host "[*] Collecting installed hotfixes"
        $xmlWriter.WriteStartElement("Hotfixes")
            
        if (Get-Command Get-HotFix -ErrorAction SilentlyContinue){
            $hotfixes = Get-HotFix
        
            foreach ($h in $hotfixes ) {
                $xmlWriter.WriteStartElement("Hotfix")
                $xmlWriter.WriteAttributeString("id",  [string] $h.HotFixID);
                $xmlWriter.WriteAttributeString("InstalledOn",[string] $h.InstalledOn);
                $xmlWriter.WriteAttributeString("Description",[string] $h.Description);
                $xmlWriter.WriteEndElement() # hotfix
            }
        } else {
            $hotfixes = Get-WmiObject -Class win32_QuickFixEngineering
        
            foreach ($h in $hotfixes ) {
                $xmlWriter.WriteStartElement("Hotfix")
                $xmlWriter.WriteAttributeString("id",  [string] $h.HotFixID);
                $xmlWriter.WriteAttributeString("InstalledOn",[string] $h.InstalledOn);
                $xmlWriter.WriteAttributeString("Description",[string] $h.Description);
                $xmlWriter.WriteEndElement() # hotfix
            }
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
                    $xmlWriter.WriteAttributeString("MacAddress", [string] $n.MacAddress);
                    $xmlWriter.WriteAttributeString("Status",[string] $n.Status);
                    $xmlWriter.WriteAttributeString("Name",[string] $n.Name);
                    $xmlWriter.WriteAttributeString("Type",[string] $n.AdapterType);
                    $xmlWriter.WriteAttributeString("InterfaceDescription",[string] $n.Description);
                    $xmlWriter.WriteEndElement() # netadapter
                }
            }catch{}
        }
        
        #######################################################################
        # Collecting information about ip addresses
        #######################################################################
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
                $netadapters = get-wmiobject -Class win32_networkadapter
                $xmlWriter.WriteStartElement("NetIPAddresses")
                 foreach ($n in $netadapters ) {
                    $xmlWriter.WriteStartElement("NetIPAddress")
                    $xmlWriter.WriteAttributeString("IP",[string] $n.NetworkAddresses);
                    $xmlWriter.WriteAttributeString("InterfaceAlias",[string] $n.Name);
                    $xmlWriter.WriteEndElement() # netadapter
                }
                $xmlWriter.WriteEndElement() # NetIPAddress
            }catch{}
        }

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
                $folder = Split-Path -Path $s.PathName
                $leaf = Split-Path -Path $s.PathName -Leaf
                $space = $leaf.IndexOf(" ")
                if ($space -eq -1) { 
                    $bin = $s.PathName
                }else{
                    $bin = $folder+"\"+$leaf.Substring(0,$space)
                }
                $xmlWriter.WriteElementString("Executable",[string]$bin);
                
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

        
        #######################################################################
        # Collecting firewall status
        #######################################################################
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
                    }catch{
                        # Ignore this ADComputer object and try to parse the next. No Tag will be added for this one. 
                    }
                }
            }catch{
                # Failed executions will be ignored and no ADComputer tags will be added under ADComputerList
            }
            $xmlWriter.WriteEndElement(); # NetFirewallProfiles
        }

        
        #######################################################################
        # Collecting WinLogon Settings
        #######################################################################

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

        
        #######################################################################
        # Installed PS Versions / Check if Version 2 is enabled 
        #######################################################################
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
                if ($entry.PowerShellVersion -eq "2.0"){
                    $v2installed = $true
                }
            }
        }
        $xmlWriter.WriteEndElement() # PSVersions
        
        $xmlWriter.WriteElementString("PSVersion2Installed", $v2installed) 
        
        #######################################################################
        # Windows Scripting Host 
        #######################################################################
        Write-Host "[*] Checking settings for Windows Scripting Host"
        
        $xmlWriter.WriteStartElement("WSH")
        
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "TrustPolicy") {
            $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name TrustPolicy -ErrorAction SilentlyContinue
            $xmlWriter.WriteElementString("TrustPolicy", $wsh.TrustPolicy)    
        }else{
            $xmlWriter.WriteElementString("TrustPolicy", "N/A")
        }
        
        
        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "Enabled") {
            $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name Enabled -ErrorAction SilentlyContinue
            if ($wsh.Enabled == 0){
                $xmlWriter.WriteElementString("Status", "Disabled")    
            }else{ 
                $xmlWriter.WriteElementString("Status", "Enabled")    
            }
        }else{
            $xmlWriter.WriteElementString("Status", "Enabled")
        }

        if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "Remote") {
            $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name Remote -ErrorAction SilentlyContinue
            if ($wsh.Enabled == 0){
                $xmlWriter.WriteElementString("Remote", "Disabled")    
            }else{ 
                $xmlWriter.WriteElementString("Remote", "Enabled")    
            }
        }else{
            $xmlWriter.WriteElementString("Remote", "Enabled")
        }
        
        $xmlWriter.WriteEndElement() # WSH

        #######################################################################
        # PS Logging enabled ? 
        #######################################################################

        
        #######################################################################
        # Check if SMBv1 is enabled  
        #######################################################################

        
        
        #######################################################################
        # Defender Status / Settings
        #######################################################################
        # Get-MpPreference
        # Get-MpComputerStatus

        if (Get-Command Get-MpPreference -ea SilentlyContinue) {
            $xmlWriter.WriteStartElement("Defender")
            $preferences = Get-MpPreference 
            $xmlWriter.WriteElementString("DisableArchiveScanning", [string] $preferences.DisableArchiveScanning) 
            $xmlWriter.WriteElementString("DisableAutoExclusions",  [string] $preferences.DisableAutoExclusions)
            $xmlWriter.WriteElementString("DisableBehaviorMonitoring",  [string] $preferences.DisableBehaviorMonitoring)   
            $xmlWriter.WriteElementString("DisableBlockAtFirstSeen",  [string] $preferences.DisableBlockAtFirstSeen)   
            $xmlWriter.WriteElementString("DisableCatchupFullScan",  [string] $preferences.DisableCatchupFullScan)   
            $xmlWriter.WriteElementString("DisableCatchupQuickScan",  [string] $preferences.DisableCatchupQuickScan)   
            $xmlWriter.WriteElementString("DisableEmailScanning",  [string] $preferences.DisableEmailScanning)   
            $xmlWriter.WriteElementString("DisableIntrusionPreventionSystem",  [string] $preferences.DisableIntrusionPreventionSystem)   
            $xmlWriter.WriteElementString("DisableIOAVProtection",  [string] $preferences.DisableIOAVProtection)   
            $xmlWriter.WriteElementString("DisableRealtimeMonitoring",  [string] $preferences.DisableRealtimeMonitoring)   
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


        #######################################################################
        # WSUS Settings in Registry
        #######################################################################
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

        #######################################################################
        # Proxy
        #######################################################################
        # [System.Net.WebProxy]::GetDefaultProxy()


    $xmlWriter.WriteEndElement() # host
$xmlWriter.WriteEndElement() # SystemInfoCollector
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()
