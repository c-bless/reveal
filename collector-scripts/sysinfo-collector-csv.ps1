<# 
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
    .\sysinfo-collector-csv.ps1 -Systemgroup PCS7 -Location "Control room" -Label "Inventory Number"
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

$dir_name = $path.Path + "\" + $hostname
try{
    $folder = New-Item -ItemType Directory -Path $dir_name -ErrorAction SilentlyContinue
}catch {}
$file_prefix = $dir_name + "\" + $hostname


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


# Get Systeminformation
Write-Host "[*] Collecting general computer infos."

###############################################################################################################
# Collecting basic information about the system
# This includes OS Name, OS Version)
###############################################################################################################
$host_info = [PSCustomObject]@{}
# if Get-ComputerInfo is available this command will be used to collect basic computer information.
# This cmdlet was introduced in Windows PowerShell 5.1. Thus, for older versions a combination of WMI querries is used.
if (Get-Command Get-ComputerInfo -ErrorAction SilentlyContinue){
    # we have at least PowerShell 5.1
    $compInfo = Get-ComputerInfo

    $osversion = ""
    if ([string]::IsNullOrEmpty($compInfo.OSVersion)){
        try{
            $osversion = [string] $compInfo.WindowsVersion;
        }catch{}
    }else{
            $osversion = [string] $compInfo.OSVersion;
    }
    $osname = ""

    if ([string]::IsNullOrEmpty($compInfo.OSName)){
        try{
            $osname = [string] $compInfo.WindowsProductName;
        }catch{}
    }else{
        $osname = [string] $compInfo.OSName;
    }

    $host_info = [PSCustomObject]@{
        OSBuildNumber = [string] [System.Environment]::OSVersion.Version.Build
        Version = "$version"
        Type = "Windows"
        SystemGroup =  $Systemgroup
        Location = $Location
        Label = $Label
        Hostname = $hostname
        Domain = [string] $compInfo.CsDomain
        DomainRole = [string] $compInfo.CsDomainRole
        OSVersion = $osversion
        OSName = $osname
        OSInstallDate =[string] $compInfo.OSInstallDate
        OSProductType = [string] $compInfo.OSProductType
        LogonServer = [string] $compInfo.LogonServer
        TimeZone = [string]$compInfo.TimeZone
        KeyboardLayout = [string]$compInfo.KeyboardLayout
        HyperVisorPresent = [string]$compInfo.HyperVisorPresent
        DeviceGuardSmartStatus = [string]$compInfo.DeviceGuardSmartStatus
        PrimaryOwnerName = [string] $compInfo.CSPrimaryOwnerName
        Whoami = [string] [System.Environment]::UserName
        WhoamiIsAdmin = [string] ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        PSVersion = [string]$PSVersionTable.PSVersion
        PSVersion2Installed = ""
        LastUpdate = [string] "N/A"
    }

}else{
    # No Get-ComputerInfo command. Thus, info must be collected using multiple technics
    $domain = [string] [System.Environment]::UserDomainName;
    $domainRole = ""
    $hypervisor = ""
    $installDate = ""
    $manufacturer = ""
    $model = ""
    $PrimaryOwnerName = ""
    $osversion = ""
    $osname = ""
    $timezoneString = ""
    try{
        $cs = Get-WmiObject -Class win32_ComputerSystem -Property *
        $domainRole = [string] $cs.DomainRole;
        $hypervisor = [string]$cs.HypervisorPresent;
        $installDate = [string] $cs.InstallDate;
        $manufacturer = [string] $cs.CsManufacturer;
        $model = [string] $cs.CsModel;
        $PrimaryOwnerName = [string] $cs.PrimaryOwnerName;
    } catch{}
    try{
        $os = Get-WmiObject Win32_OperatingSystem
        $osversion = [string] $os.Version;
        $osname = [string] $os.Caption;
    } catch {
        $osversion = [string] [System.Environment]::OSVersion.Version;
        $osname =  [string] [System.Environment]::OSVersion.VersionString;
    }
    try {
        $timezone = Get-WmiObject -Class win32_timezone
        $timezoneString =  $timezone.Caption;
    }catch{}

    $host_info = [PSCustomObject]@{
        OSBuildNumber = [string] [System.Environment]::OSVersion.Version.Build
        Version = "$version"
        Type = "Windows"
        SystemGroup =  $Systemgroup
        Location = $Location
        Label = $Label
        Hostname = $hostname
        Domain = $domain
        DomainRole = $domainRole
        OSVersion = $osversion
        OSName = $osname
        OSInstallDate = $installDate
        Manufacturer = $manufacturer
        TimeZone = $timezoneString
        Model = $model
        HyperVisorPresent = $hypervisor
        PrimaryOwnerName = $PrimaryOwnerName
        Whoami = [string] [System.Environment]::UserName
        WhoamiIsAdmin = [string] ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        PSVersion = [string]$PSVersionTable.PSVersion
        LastUpdate = [string] "N/A"
        PSVersion2Installed = ""
    }
}


###############################################################################################################
# Collecting information about the BIOS
###############################################################################################################
try{
    $bios = Get-WmiObject -Class win32_bios
    $bios_info =  [PSCustomObject]@{
        Manufacturer = [string] $bios.Manufacturer
        Name = [string] $bios.Name
        Version = [string] $bios.Version
        SerialNumber = [string] $bios.SerialNumber
    } | export-csv -Path $file_prefix"-bios.csv"

}catch{}


###############################################################################################################
# Collecting information about installed hotfixes / patches
###############################################################################################################
Write-Host "[*] Collecting installed hotfixes"

if (Get-Command Get-HotFix -ErrorAction SilentlyContinue){
    $hotfixes = Get-HotFix
    if ( $hotfixes.Length -gt 0 ){
        $lastUpdate = $hotfixes[0]
        $host_info.LastUpdate = [string] $lastUpdate.InstalledOn;
    }
    $hotfixes | Select HotFixId,InstalledOn,Description| Export-Csv -Path $file_prefix"-hotfixes.csv"
} else {
    try{
        $hotfixes = Get-WmiObject -Class win32_QuickFixEngineering | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue
    } catch {
        $hotfixes = Get-WmiObject -Class win32_QuickFixEngineering
    }
    if ( $hotfixes.Length -gt 0 ){
        $lastUpdate = $hotfixes[0]
        $host_info.LastUpdate = [string] $lastUpdate.InstalledOn;
    }
    $hotfixes | Select HotFixId,InstalledOn,Description| Export-Csv -Path $file_prefix"-hotfixes.csv"
}



 ###############################################################################################################
# Collecting information about installed products / applications
###############################################################################################################

Write-Host "[*] Collecting installed products"
$products = Get-WmiObject  -class win32_product
$products | select Caption,InstallDate,Description,Vendor,Name,Version,InstallLocation | Export-Csv -Path $file_prefix"-products.csv"




###############################################################################################################
# Collecting information about network adapters
###############################################################################################################
Write-Host "[*] Collecting available network adapters"
if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
    $netadapters = Get-NetAdapter
    $netadapters | Select MacAddress,Status,Name,InterfaceDescription | Export-CSV -Path $file_prefix"-netadapter.csv"
}else{
    try{
        $netadapters = get-wmiobject -Class win32_networkadapter
        $netadapters | Select MacAddress,Status,Name,AdapterType,Description | Export-CSV -Path $file_prefix"-netadapter-wmi.csv"
    }catch{}
}



###############################################################################################################
# Collecting information about ip addresses
###############################################################################################################

if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue ) {
    Write-Host "[*] Collecting IP addresses"
    $netips = Get-NetIPAddress
    $netips | Select AddressFamily,Type,IPAddress,PrefixLength,InterfaceAlias | Export-CSV -Path $file_prefix"-netipaddresses.csv"
} else {
    $adapter_list = New-Object System.Collections.ArrayList
    try{
        $netadapters = get-wmiobject -Class win32_networkadapterconfiguration -Filter "IPEnabled = 'True'"
        foreach ($n in $netadapters ) {
            foreach ($i in $n.IPAddress){
                [void] $adapter_list.Add([PSCustomObject]@{
                    IP = [string] $i
                    InterfaceAlias = [string] $n.Caption
                    DHCP = [string] $n.DHCPEnabled
                })
            }
        }
    $adapter_list| Export-CSV -Path $file_prefix"-netipaddresses-wmi.csv"
    }catch{}
}


###############################################################################################################
# Collecting information about available routes (routing table)
###############################################################################################################
Write-Host "[*] Collecting routing table"

if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
    try{
        $routes = Get-NetRoute
        $routes | select AddressFamily,DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,ifIndex,InterfaceMetric,IsStatic,AdminDistance | Export-CSV -Path $file_prefix"-routes.csv"
    }catch{}
}




###############################################################################################################
# Collecting information about services
###############################################################################################################

Write-Host "[*] Collecting service information"
$services = Get-WmiObject  -class win32_service

$services | select Caption,Description,Name,StartMode,PathName,Started,StartName,SystemName,DisplayName,Running,AcceptStop,AcceptPause,ProcessId,DelayedAutoStart| Export-CSV -Path $file_prefix"-services.csv"

$service_acls = New-Object System.Collections.ArrayList
foreach ($s in $services ) {
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


        $space2 = $bin.IndexOf('"')
        if ($space2 -ne -1){
            $bin =$bin.Replace('"','')
        }

        $acl = get-acl -Path $bin -ErrorAction SilentlyContinue
        foreach ($a in $acl.Access) {
            try{
                [void] $service_acls.Add([PSCustomObject]@{
                        Name = [string] $s.Name
                        Executable = [string]$bin
                        AccountName = [string] $a.IdentityReference
                        AccessControlType = [string] $a.AccessControlType
                        AccessRight = [string] $a.FileSystemRights
                    })
            }catch{}
        }
    } catch {}
}

$service_acls | Export-CSV -Path $file_prefix"-service_acls.csv"

###############################################################################################################
# Collecting information about local user accounts
###############################################################################################################

# using WMI to be compatible with older PS versions
Write-Host "[*] Collecting local user accounts"
$users = Get-WmiObject -class win32_useraccount -Filter "LocalAccount=True"
$users | select AccountType,Domain,Disabled,LocalAccount,Name,FullName,Description,SID,Lockout,PasswordChangeable,PasswordExpires,PasswordRequired | Export-CSV -Path $file_prefix"-users.csv"


###############################################################################################################
# Collecting information about local groups
###############################################################################################################
Write-Host "[*] Collecting local groups"
$groups = Get-WmiObject -class win32_group -Filter "LocalAccount=True"

$groups | select Name,Caption,Description,LocalAccount,SID | Export-CSV -Path $file_prefix"-groups.csv"
$group_members = New-Object System.Collections.ArrayList

foreach ($g in $groups ) {

        $groupname = [string] $g.Name
        Write-Host "[*] - Enumerating members of group: $groupname"
        $query="Associators of {Win32_Group.Domain='$hostname',Name='$groupname'} where Role=GroupComponent"
        $members = get-wmiobject -query $query -ComputerName $hostname
        foreach ($m in $members){
            [void] $group_members.Add([PSCustomObject]@{
                Groupname = $groupname
                AccountType = [string] $m.AccountType
                Domain = [string] $m.Domain
                Name = [string] $m.Name
                SID = [string] $m.SID
                Caption = [string] $m.Caption
            });
        }
}
$group_members | Export-CSV -Path $file_prefix"-group_members.csv"

###############################################################################################################
# Collecting information about shares on the system
###############################################################################################################
Write-Host "[*] Collecting information about shares"
$shares = Get-WmiObject -class win32_share
$shares | select Name,Path,Description | Export-CSV -Path $file_prefix"-shares.csv"

$share_acls = New-Object System.Collections.ArrayList
$ntfs_acls = New-Object System.Collections.ArrayList

foreach ($s in $shares ) {

    ## Get ACLs (NTFS)
    $path = [string] $s.Path
    try {
        $acl = get-acl -Path $path -ErrorAction SilentlyContinue
        foreach ($a in $acl.Access) {
            [void] $ntfs_acls.Add([PSCustomObject]@{
                Share = $s.Name
                Name = [string] $s.Name
                AccountName = [string] $a.IdentityReference
                AccessControlType = [string] $a.AccessControlType
                AccessRight = [string] $a.FileSystemRights
            })
        }
    } catch {}
    if (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue) {
        try {
            $acl = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
            foreach ($a in $acl) {
               [void]  $share_acls.Add([PSCustomObject]@{
                    Share = $s.Name
                    Name = [string] $s.Name
                    ScopeName = [string] $a.ScopeName
                    AccountName = [string] $a.AccountName
                    AccessControlType = [string] $a.AccessControlType
                    AccessRight = [string] $a.AccessRight
                })
            }
        } catch {}
    }else{
        try {
            $share = "\\" + $hostname  +"\"+  [string]$s.Name
            $acl = get-acl -Path $share -ErrorAction SilentlyContinue
            foreach ($a in $acl.Access) {
                [void] $share_acls.Add([PSCustomObject]@{
                    Share = $s.Name
                    Name = [string] $s.Name
                    ScopeName = ""
                    AccountName = [string] $a.IdentityReference
                    AccessControlType = [string] $a.AccessControlType
                    AccessRight = [string] $a.FileSystemRights
                })
            }
        } catch {}
    }
}
$share_acls | Export-CSV -Path $file_prefix"-share_acls.csv"
$ntfs_acls | Export-CSV -Path $file_prefix"-share_ntfs_acls.csv"




###############################################################################################################
# Collecting WSUS Settings in Registry
###############################################################################################################
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd939844(v=ws.10)?redirectedfrom=MSDN

Write-Host "[*] Checking WSUS configuration"
$wsus_settings = [PSCustomObject]@{
    AcceptTrustedPublisherCerts = ""
    DisableWindowsUpdateAccess = ""
    ElevateNonAdmins = ""
    TargetGroup = ""
    TargetGroupEnabled = ""
    WUServer = ""
    WUStatusServer = ""
}
if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "AcceptTrustedPublisherCerts") {
    $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name AcceptTrustedPublisherCerts -ErrorAction SilentlyContinue
    $wsus_settings.AcceptTrustedPublisherCerts = [string] $wsus.AcceptTrustedPublisherCerts
}
if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "DisableWindowsUpdateAccess") {
    $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name DisableWindowsUpdateAccess -ErrorAction SilentlyContinue
    $wsus_settings.DisableWindowsUpdateAccess = [string] $wsus.DisableWindowsUpdateAccess
}
if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "ElevateNonAdmins") {
    $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name ElevateNonAdmins -ErrorAction SilentlyContinue
    $wsus_settings.ElevateNonAdmins = [string] $wsus.ElevateNonAdmins
}
if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "TargetGroup") {
    $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name TargetGroup -ErrorAction SilentlyContinue
    $wsus_settings.TargetGroup = [string]  $wsus.TargetGroup
}
if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "TargetGroupEnabled") {
    $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name TargetGroupEnabled -ErrorAction SilentlyContinue
    $wsus_settings.TargetGroupEnabled = [string]  $wsus.TargetGroupEnabled
}
if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "WUServer") {
    $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue
    $wsus_settings.WUServer = [string]  $wsus.WUServer
}
if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "WUStatusServer") {
    $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name WUStatusServer -ErrorAction SilentlyContinue
    $wsus_settings.WUStatusServer = [string]   $wsus.WUStatusServer
}
$wsus_settings | export-csv -Path $file_prefix"-wsus.csv"

###############################################################################################################
# Collecting firewall status
###############################################################################################################

if (Get-Command Get-NetFirewallProfile -ea SilentlyContinue) {
    Write-Host "[*] Collecting local firewall state"
    try{
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        $profiles | Export-CSV -Path $file_prefix"-fwprofiles.csv"
        foreach ($p in $profiles) {
            try{
                if (!$p.Enabled){
                    $result = [PSCustomObject]@{
                        Component = 'Firewall'
                        Name = 'FirewallEnabled'
                        Method       = 'Get-NetFirewallProfile'
                        Key   = $p.Name
                        Value      = $p.Enabled
                        Result = 'Firewall is not enabled for the profile'
                    }
                    [void] $config_checks.Add($result)
                }
            }catch{}
        }
    }catch{}
}


###############################################################################################################
# Collecting WinLogon Settings
###############################################################################################################
Write-Host "[*] Checking autologon configuration"
$winlogon_settings = [PSCustomObject]@{
    DefaultUserName = ""
    DefaultPassword = ""
    DefaultPasswordBase64 = ""
    DefaultPasswordEncrypted = ""
    AutoAdminLogon = ""
    ForceAutoLogon = ""
    DefaultDomain = ""
}
if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultUserName") {
    $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue
    $winlogon_settings.DefaultUserName = $value.DefaultUserName;
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
    $winlogon_settings.DefaultPasswordBase64 = [string] $base64
    $winlogon_settings.DefaultPasswordEncrypted = [string] $encrypted
    $winlogon_settings.DefaultPassword = $defaultPassword
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
    $winlogon_settings.AutoAdminLogon = $value.AutoAdminLogon
}
if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "ForceAutoLogon") {
    $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ForceAutoLogon -ErrorAction SilentlyContinue
    $winlogon_settings.ForceAutoLogon = $value.ForceAutoLogon
}
if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultDomainName") {
    $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue
    $winlogon_settings.DefaultDomain = $value.DefaultDomain
}
$winlogon_settings | Export-CSV -Path $file_prefix"-winlogon.csv"

###############################################################################################################
# Collecting information about Installed PS Versions / Check if Version 2 is enabled
###############################################################################################################

Write-Host "[*] Checking installed PS versions"

$v2installed = $false

$entries = New-Object System.Collections.ArrayList

$ids = (1..5)
foreach ( $id in $ids) {
    $entry =  Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\$id\PowerShellEngine -ErrorAction SilentlyContinue
    if ($entry) {
        [void] $entries.Add([PSCustomObject]@{
            Version = [string] $entry.PowerShellVersion
            PSCompatibleVersion = [string] $entry.PSCompatibleVersion
            PSPath = [string] $entry.PSPath
            RuntimeVersion = [string] $entry.RuntimeVersion
            ConsoleHostModuleName = [string] $entry.ConsoleHostModuleName
        })
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
$entries | Export-csv -Path $file_prefix"-powershell.csv"

$host_info.PSVersion2Installed = [string] $v2installed

###############################################################################################################
# Collecting information about Windows Scripting Host
###############################################################################################################

Write-Host "[*] Checking settings for Windows Scripting Host"


#######################################################################
$wsh_trust_policy =""
if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "TrustPolicy") {
    $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name TrustPolicy -ErrorAction SilentlyContinue
    $wsh_trust_policy = [string] $wsh.TrustPolicy
}else{
    $wsh_trust_policy = "N/A"
}
#$xmlWriter.WriteElementString("TrustPolicy", $wsh_trust_policy)
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
#$xmlWriter.WriteElementString("EnabledStatus", $wsh_enabled_status)
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

#$xmlWriter.WriteElementString("RemoteStatus", $wsh_remote_status)

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

###############################################################################################################
# Check if LLMNR is enabled
###############################################################################################################
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

$ntp = [PSCustomObject]@{
    Server = ""
    Type = ""
    UpdateInterval = ""
}

if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "NtpServer") {
    $ntpServer =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name NtpServer -ErrorAction SilentlyContinue
    $ntp.Server = [string] $ntpServer.NtpServer
}
if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "Type") {
    $ntpType =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name Type -ErrorAction SilentlyContinue
    # NT5DS - Used for domain-joined computers
    # NTP - Used for non-domain-joined computers
    $ntp.Type = [string] $ntpType.Type
}
if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"  -ea SilentlyContinue).Property -contains "UpdateInterval") {
    $interval =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name UpdateInterval -ErrorAction SilentlyContinue
    # default is 30000 for domain-joined computers
    # default is 360000 for non-domain-joined computers
    $ntp.UpdateInterval = [string] $interval.UpdateInterval
}
$ntp | export-csv -Path $file_prefix"-ntp.csv"

###############################################################################################################
# Collecting information about PowerShell (PS Logging enabled ?)
###############################################################################################################

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
Write-Host "[*] Checking PS Logging is enabled"

if ((get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"  -ea SilentlyContinue).Property -contains "EnableScriptBlockLogging") {
    $logging =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
    if ($logging -eq 1){
        $host_info.PSScriptBlockLogging = "Enabled"
    }else{
        $host_info.PSScriptBlockLogging = "Disabled"
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


$smb_settings = [PSCustomObject]@{
   Method = ""
   SMB1Enabled = ""
   SMB2Enabled = ""
   EncryptData = ""
   EnableSecuritySignature = ""
   RequireSecuritySignature = ""
}

if (Get-Command Get-SmbServerConfiguration -ea SilentlyContinue) {
    # Cmdlet has been introduced in Windows 8, Windows Server 2012
    $smb_settings.Method = "Get-SmbServerConfiguration"
    $smb = Get-SmbServerConfiguration
    $smb_settings.SMB1Enabled = [string] $smb.EnableSMB1Protocol
    $smb_settings.SMB2Enabled = [string] $smb.EnableSMB2Protocol
    $smb_settings.EncryptData = [string] $smb.EncryptData
    $smb_settings.EnableSecuritySignature = [string] $smb.EnableSecuritySignature
    $smb_settings.RequireSecuritySignature = [string] $smb.RequireSecuritySignature

} else {
    $smb_method= "Registry"
    # older Windows versions can check the registry.
    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "SMB1") {
        $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue
        if ($smb1 -eq 0){
            $smb_settings.SMB1Enabled = "False"
        } else{
            $smb_settings.SMB1Enabled = "True"

        }
    } else {
        # Enabled by default. Since the entry does not exist it is enabled
        $smb_settings.SMB1Enabled = "True"
    }

    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "SMB2") {
        $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -ErrorAction SilentlyContinue
        if ($smb1 -eq 0){
            $smb_settings.SMB2Enabled =  "False"
        } else{
            $smb_settings.SMB2Enabled = "True"

        }
    } else {
        # Enabled by default. Since the entry does not exist it is enabled
        $smb_settings.SMB2Enabled =  "True"
    }

    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "EnableSecuritySignature") {
        $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name EnableSecuritySignature -ErrorAction SilentlyContinue
        $smb_settings.EnableSecuritySignature = [string] $smb.EnableSecuritySignature
    }

    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "RequireSecuritySignature") {
        $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -ErrorAction SilentlyContinue
        $smb_settings.RequireSecuritySignature = [string] $smb.RequireSecuritySignature
    }
}

$smb_settings | Export-CSV -Path $file_prefix"-smb_settings.csv"

###############################################################################################################
# Collecting information about Defender (Status / Settings)
###############################################################################################################

Write-Host "[*] Checking Defender settings"
# Get-MpPreference
# Get-MpComputerStatus

if (Get-Command Get-MpPreference -ea SilentlyContinue) {
    $preferences = Get-MpPreference
    $preferences | select DisableArchiveScanning,DisableAutoExclusions,DisableBehaviorMonitoring,DisableBlockAtFirstSeen,DisableCatchupFullScan,DisableCatchupQuickScan,DisableEmailScanning,DisableIntrusionPreventionSystem,DisableIOAVProtection,DisableRealtimeMonitoring,DisableRemovableDriveScanning,DisableRestorePoint,DisableScanningMappedNetworkDrivesForFullScan,DisableScanningNetworkFiles,DisableScriptScanning,EnableNetworkProtection,ExclusionPath,ExclusionProcess | Export-CSV -Path $file_prefix"-defender.csv"
}

###############################################################################################################
# Collecting information about Printer
###############################################################################################################

Write-Host "[*] Checking if printers are installed"
if (Get-Command Get-Printer -ea SilentlyContinue) {
    try {
        $printers = Get-Printer -ea SilentlyContinue
        $printers | select Name,ShareName,Type,DriverName,PortName,Shared,Published | export-csv -Path $file_prefix"-printer.csv"
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

$file_checks_results | Export-CSV -Path $file_prefix"-FileExistChecks.csv"

###############################################################################################################
# Perform: Path ACL Checks
###############################################################################################################
Write-Host "[*] Checking ACLs for specified pathes"
# ArrayList of pathes that should be checked
$acl_path_checks = New-Object System.Collections.ArrayList
$acl_path_check_results = New-Object System.Collections.ArrayList

[void]$acl_path_checks.Add('C:\')
[void]$acl_path_checks.Add('C:\Program Files\')
[void]$acl_path_checks.Add('C:\Program Files (x86)\')

foreach ($c in $acl_path_checks){
    $path = [string] $c
    if (Test-Path $path){
        $acl = get-acl -Path $path -ErrorAction SilentlyContinue
        foreach ($a in $acl.Access) {
            try{
                [void] $acl_path_check_results.Add([PSCustomObject]@{
                    Path = [string] $path
                    AccountName = [string] $a.IdentityReference
                    AccessControlType = [string] $a.AccessControlType
                    AccessRight = [string] $a.FileSystemRights
                })
            }catch{}
        }
    }
}
$acl_path_check_results | Export-CSV -Path $file_prefix"-file_path_checks.csv"

###############################################################################################################
# Adding ConfigChecks to csv.
###############################################################################################################
$config_checks | Export-csv -Path $file_prefix"-config-checks.csv"
           
            

# write hostinfo
$host_info | Export-CSV -Path $file_prefix"-hostinfo.csv"