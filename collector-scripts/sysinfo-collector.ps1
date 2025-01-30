<#
    .SYNOPSIS
    This PowerShell script is to fetch system information.

    .DESCRIPTION
    This PowerShell script is to fetch system information. The collector script is published as part of "REVEAL".
    https://github.com/c-bless/reveal

    Author:     Christoph Bless (github@cbless.de)
    Version:    0.6
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
$version="0.6"

$date = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME

# can be generated with helper script ./genkey.py
$encKey = (7, 16, 166, 10, 141, 23, 37, 94, 240, 162, 206, 168, 181, 97, 19, 170)

$path = Get-Location


###################################################################################################################
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
$config_check_results = New-Object System.Collections.ArrayList
###################################################################################################################


###################################################################################################################
# ArrayList to store results from file existence checks. Those will be added as FileExistence-Tags.
###################################################################################################################
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


###################################################################################################################


###################################################################################################################
# ArrayList to store results from configuration checks. Those will be added as ConfigCheck-Tags at the end of the
###################################################################################################################

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

###################################################################################################################

###################################################################################################################
# ArrayList of pathes that should be checked for ACLs
###################################################################################################################
# ArrayList of pathes that should be checked
$acl_path_checks = New-Object System.Collections.ArrayList

[void]$acl_path_checks.Add('C:\')
[void]$acl_path_checks.Add('C:\Program Files\')
[void]$acl_path_checks.Add('C:\Program Files (x86)\')

# [MODIFY ME: ADD ADDITIONAL PATHES HERE]

###################################################################################################################
# Function to get the results of the registry checks
###################################################################################################################
function Collect-RegistryChecks {
    <#
    .SYNOPSIS
    This function checks the registry for specific keys and values.
    .DESCRIPTION
    The Get-RegistryChecks function is designed to perform registry checks based on a list of registry check
    definitions provided as input. It iterates through each registry check definition, verifies the existence of the
    specified registry key and value, and compares the current value with the expected value. The results of these
    checks are stored in a custom object and added to an array list, which is then returned by the function.
    .PARAMETER RegistryChecks (System.Collections.ArrayList)
    An array list containing registry check definitions. Each registry check definition is a custom object with the
    following properties:
    - Category: The category of the registry check.
    - Tags: Tags associated with the registry check.
    - Name: The name of the registry check.
    - Description: A description of the registry check.
    - Path: The registry path to be checked.
    - Key: The registry key to be checked.
    - Expected: The expected value of the registry key.
    .OUTPUTS
    An array list containing the results of the registry checks. Each result is a custom object with the following
    properties:
    - Category: The category of the registry check.
    - Tags: Tags associated with the registry check.
    - Name: The name of the registry check.
    - Description: A description of the registry check.
    - Path: The registry path to be checked.
    - Key: The registry key to be checked.
    - Expected: The expected value of the registry key.
    - KeyExists: A boolean value indicating whether the registry key exists.
    - ValueMatch: A boolean value indicating whether the current value matches the expected value.
    - CurrentValue: The current value of the registry key.
    #>
    param (
        [System.Collections.ArrayList]$RegistryChecks
    )

    $registry_check_results = New-Object System.Collections.ArrayList

    foreach ($c in $RegistryChecks){
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
    return $registry_check_results
}


function RegistryChecksToXML{
    <#
    .SYNOPSIS
    This function writes the results of the registry checks to an XML file.
    .DESCRIPTION
    The RegistryChecksToXML function is designed to write the results of the registry checks to an XML file. It takes
    an array list containing the results of the registry checks and an XML writer object as input.
    .PARAMETER xmlWriter (System.Xml.XmlWriter)
    An XML writer object used to write the results of the registry checks to an XML file.
    .PARAMETER registry_check_results (System.Collections.ArrayList)
    An array list containing the results of the registry checks. Each result is a custom object with the following
    properties:
    - Category: The category of the registry check.
    - Tags: Tags associated with the registry check.
    - Name: The name of the registry check.
    - Description: A description of the registry check.
    - Path: The registry path to be checked.
    - Key: The registry key to be checked.
    - Expected: The expected value of the registry key.
    - KeyExists: A boolean value indicating whether the registry key exists.
    - ValueMatch: A boolean value indicating whether the current value matches the expected value.
    - CurrentValue: The current value of the registry key.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$registry_check_results
    )

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
}

function Collect-FileExistCheck {
    <#
    .SYNOPSIS
    This function checks if a file exists and if the hash of the file matches the expected hash.
    .DESCRIPTION
    The Collect-FileExistCheck function is designed to check if a file exists and if the hash of the file matches the
    expected hash. It takes an array list containing file check definitions as input and returns an array list
    containing the results of the file checks.
    .PARAMETER file_checks (System.Collections.ArrayList)
    An array list containing file check definitions. Each file check definition is a custom object with the following
    properties:
    - Name: The name of the file check.
    - File: The path to the file to be checked.
    - ExpectedHASH: The expected hash of the file.
    .OUTPUTS
    An array list containing the results of the file checks. Each result is a custom object with the following
    properties:
    - Name: The name of the file check.
    - File: The path to the file to be checked.
    - ExpectedHASH: The expected hash of the file.
    - FileExist: A boolean value indicating whether the file exists.
    - HashMatch: A boolean value indicating whether the hash of the file matches the expected hash.
    - HashChecked: A boolean value indicating whether the hash of the file has been checked.
    - CurrentHash: The current hash of the file.
    #>
    param (
        [System.Collections.ArrayList]$file_checks
    )

    $file_checks_results = New-Object System.Collections.ArrayList

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
    return $file_checks_results
}


function FileExistChecksToXML{
    <#
    .SYNOPSIS
    This function writes the results of the file existence checks to an XML file.
    .DESCRIPTION
    The FileExistChecksToXML function is designed to write the results of the file existence checks to an XML file. It
    takes an array list containing the results of the file existence checks and an XML writer object as input.
    .PARAMETER xmlWriter (System.Xml.XmlWriter)
    An XML writer object used to write the results of the file existence checks to an XML file.
    .PARAMETER file_checks_results (System.Collections.ArrayList)
    An array list containing the results of the file existence checks. Each result is a custom object with the following
    properties:
    - Name: The name of the file check.
    - File: The path to the file to be checked.
    - ExpectedHASH: The expected hash of the file.
    - FileExist: A boolean value indicating whether the file exists.
    - HashMatch: A boolean value indicating whether the hash of the file matches the expected hash.
    - HashChecked: A boolean value indicating whether the hash of the file has been checked.
    - CurrentHash: The current hash of the file.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$file_checks_results
    )
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
}


function Collect-HostInfo {
    <#
    .SYNOPSIS
    Collects general information about the host system.

    .DESCRIPTION
    The Collect-HostInfo function gathers various details about the host system, such as OS version, domain information,
    and user details. It uses the Get-ComputerInfo cmdlet if available, otherwise, it falls back to WMI queries for
    older PowerShell versions.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the collected host information.

    .EXAMPLE
    $hostInfo = Collect-HostInfo
    #>
    $host_info = [PSCustomObject]@{}
    if (Get-Command Get-ComputerInfo -ErrorAction SilentlyContinue){
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
            if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue){
                $cs = Get-CimInstance -Class win32_ComputerSystem -Property *
            }else{
                $cs = Get-WmiObject -Class win32_ComputerSystem -Property *
            }
            $domainRole = [string] $cs.DomainRole;
            $hypervisor = [string]$cs.HypervisorPresent;
            $installDate = [string] $cs.InstallDate;
            $manufacturer = [string] $cs.CsManufacturer;
            $model = [string] $cs.CsModel;
            $PrimaryOwnerName = [string] $cs.PrimaryOwnerName;
        } catch{}
        try {
            if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue){
                $os = Get-CimInstance -Class win32_OperatingSystem -Property *
            }else{
                $timezone = Get-WmiObject -Class win32_timezone
            }
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
    return $host_info
}

function HostInfo-ToXML {
    <#
    .SYNOPSIS
    Writes the host information to an XML file.
    .DESCRIPTION
    The HostInfo-ToXML function is designed to write the host information to an XML file. It takes a custom object
    containing the host information and an XML writer object as input.
    .PARAMETER xmlWriter (System.Xml.XmlWriter)
    An XML writer object used to write the host information to an XML file.
    .PARAMETER hostInfo (PSCustomObject)
    A custom object containing the host information.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$hostInfo
    )

    $xmlWriter.WriteElementString("SystemGroup",[string] $hostInfo.SystemGroup)
    $xmlWriter.WriteElementString("Location",[string] $hostInfo.Location)
    $xmlWriter.WriteElementString("Label",[string] $hostInfo.Label)
    $xmlWriter.WriteElementString("Hostname",[string] $hostInfo.Hostname)
    $xmlWriter.WriteElementString("Domain",[string] $hostInfo.Domain)
    $xmlWriter.WriteElementString("DomainRole",[string] $hostInfo.DomainRole);
    $xmlWriter.WriteElementString("OSBuildNumber",[string] $hostInfo.OSBuildNumber)
    $xmlWriter.WriteElementString("OSVersion",[string] $hostInfo.OSVersion);
    $xmlWriter.WriteElementString("OSName", [string] $hostInfo.OSName);
    $xmlWriter.WriteElementString("OSInstallDate",[string] $hostInfo.OSInstallDate);
    $xmlWriter.WriteElementString("OSProductType",[string] $hostInfo.OSProductType);
    $xmlWriter.WriteElementString("LogonServer", [string] $hostInfo.LogonServer);
    $xmlWriter.WriteElementString("TimeZone",[string]$hostInfo.TimeZone);
    $xmlWriter.WriteElementString("KeyboardLayout",[string]$hostInfo.KeyboardLayout);
    $xmlWriter.WriteElementString("HyperVisorPresent",[string]$hostInfo.HyperVisorPresent);
    $xmlWriter.WriteElementString("DeviceGuardSmartStatus",[string]$hostInfo.DeviceGuardSmartStatus);
    $xmlWriter.WriteElementString("PrimaryOwnerName",[string] $hostInfo.CSPrimaryOwnerName);
    $xmlWriter.WriteElementString("Whoami", [string] $hostInfo.Whoami);
    $xmlWriter.WriteElementString("WhoamiIsAdmin", [string] $hostInfo.WhoamiIsAdmin);
    $xmlWriter.WriteElementString("PSVersion",[string]$hostInfo.PSVersion);
    $xmlWriter.WriteElementString("PSVersion2Installed",[string]$hostInfo.PSVersion2Installed);
    $xmlWriter.WriteElementString("LastUpdate",[string] $hostInfo.LastUpdate);
}



###################################################################################################################
# Functions collect and export BIOS information
###################################################################################################################
function Collect-BIOSInfo {
    <#
    .SYNOPSIS
    Collects BIOS information from the host system.
    .DESCRIPTION
    The Collect-BIOSInfo function gathers information about the BIOS of the host system, such as the manufacturer,
    version, and serial number. It uses the Get-WmiObject cmdlet to query the win32_bios class for this information.
    .OUTPUTS
    [PSCustomObject]
    A custom object containing the collected BIOS information.
    #>
    if (Get-Command CimInstance -ErrorAction SilentlyContinue){
        $bios = Get-CimInstance -Class win32_bios
    }else{
        $bios = Get-WmiObject -Class win32_bios
    }
    $biosInfo = [PSCustomObject]@{
        Manufacturer = [string] $bios.Manufacturer;
        Name = [string] $bios.Name;
        Version = [string] $bios.Version;
        SerialNumber = [string] $bios.SerialNumber;
    }
    return $biosInfo
}

function BIOSInfo-ToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$biosInfo
    )

    $xmlWriter.WriteStartElement("BIOS")
    $xmlWriter.WriteAttributeString("Manufacturer", [string] $biosInfo.Manufacturer);
    $xmlWriter.WriteAttributeString("Name", [string] $biosInfo.Name);
    $xmlWriter.WriteAttributeString("Version", [string] $biosInfo.Version);
    $xmlWriter.WriteAttributeString("SerialNumber", [string] $biosInfo.SerialNumber);
    $xmlWriter.WriteEndElement() # BIOS
}


function Collect-Hotfixes {

    param (
        [PSCustomObject]$host_info
    )

    if (Get-Command Get-HotFix -ErrorAction SilentlyContinue){
        try{
            $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue
        } catch{
            $hotfixes = Get-HotFix
        }
    } else {

        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue){
            $hotfixes = Get-CimInstance -Class win32_QuickFixEngineering
        } else {
            $hotfixes = Get-WmiObject -Class win32_QuickFixEngineering
        }
        try{
            $hotfixes = $hotfixes | Sort-Object -Property InstalledOn -Descending -ErrorAction SilentlyContinue
            if ( $hotfixes.Length -gt 0 ){
                $lastUpdate = $hotfixes[0]
                $host_info.LastUpdate = [string] $lastUpdate.InstalledOn;
            }
        } catch {}
    }
    return $hotfixes
}


function Hotfixes-ToXML {

    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$hotfixes
    )


    $xmlWriter.WriteStartElement("Hotfixes")
    foreach ($h in $hotfixes ) {
        $xmlWriter.WriteStartElement("Hotfix")
        $xmlWriter.WriteAttributeString("id",  [string] $h.HotFixID);
        $xmlWriter.WriteAttributeString("InstalledOn",[string] $h.InstalledOn);
        $xmlWriter.WriteAttributeString("Description",[string] $h.Description);
        $xmlWriter.WriteEndElement() # hotfix
    }
    $xmlWriter.WriteEndElement() # hotfixes
}


function Collect-InstalledProducts {
    if (Get-Command CimInstance -ErrorAction SilentlyContinue){
        $products = Get-CimInstance -Class win32_product
    }else{
        $products = Get-WmiObject  -class win32_product
    }
    return $products
}

function InstalledProducts-ToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$products
    )

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
}



function Collect-NetAdapter {
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        $netadapters = Get-NetAdapter
        # Add an alias property to the object to make it compatible with the get-wmiobject object
        foreach ($n in $netadapters ) {
            $n | Add-Member -MemberType NoteProperty -Name Type -Value "N/A" -Force
        }
    }else{
        $netadapters = get-wmiobject -Class win32_networkadapter
        # Add an alias property to the object to make it compatible with the Get-NetAdapter object
        foreach ($n in $netadapters ) {
            $n | Add-Member -MemberType AliasProperty -Name InterfaceDescription -Value $n.Description
        }
    }
    return $netadapters
}


function NetAdapter-ToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$netadapters
    )

    $xmlWriter.WriteStartElement("Netadapters")
    foreach ($n in $netadapters ) {
        $xmlWriter.WriteStartElement("Netadapter")
        $xmlWriter.WriteAttributeString("MacAddress", [string] $n.MacAddress);
        try {
            $xmlWriter.WriteAttributeString("Type",[string] $n.AdapterType);
        } catch {}
        $xmlWriter.WriteAttributeString("Status",[string] $n.Status);
        $xmlWriter.WriteAttributeString("Name",[string] $n.Name);
        $xmlWriter.WriteAttributeString("InterfaceDescription",[string] $n.InterfaceDescription);
        $xmlWriter.WriteEndElement() # netadapter
    }
    $xmlWriter.WriteEndElement() # netadapters
}


function Collect-NetRoute {

    if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
        $routes = Get-NetRoute
    }else{
        $routes = New-Object System.Collections.ArrayList
    }
    return $routes
}

function NetRoute-ToXML {

    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$routes
    )

    $xmlWriter.WriteStartElement("Routes")
    foreach ($r in $routes ) {
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
    }
    $xmlWriter.WriteEndElement() # Routes

}

function Collect-NetIPAddress {
    $netips = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue ) {
        $netipaddresses = Get-NetIPAddress
        foreach ($n in $netipaddresses ) {
            $netips.Add([PSCustomObject]@{
                AddressFamily = [string] $n.AddressFamily;
                Type = [string] $n.Type;
                IP = [string] $n.IPAddress;
                Prefix = [string] $n.PrefixLength;
                InterfaceAlias = [string] $n.InterfaceAlias;
                DHCP = [string] "";
            })
        }
    } else {
        try{
            $netadapters = get-wmiobject -Class win32_networkadapterconfiguration -Filter "IPEnabled = 'True'"
            foreach ($n in $netadapters ) {
                foreach ($i in $n.IPAddress){
                    $netips.Add([PSCustomObject]@{
                        AddressFamily = [string] "";
                        Type = [string] "";
                        IP = [string] $i;
                        Prefix = [string] "";
                        InterfaceAlias = [string] $n.Caption;
                        DHCP = [string] $n.DHCPEnabled;
                    })
                }
            }
        }catch{}
    }
    return $netips
}

function NetIPAddress-ToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$netips
    )

    $xmlWriter.WriteStartElement("NetIPAddresses")
    foreach ($n in $netips ) {
        $xmlWriter.WriteStartElement("NetIPAddress")
        $xmlWriter.WriteAttributeString("AddressFamily", [string] $n.AddressFamily);
        $xmlWriter.WriteAttributeString("Type", [string] $n.Type);
        $xmlWriter.WriteAttributeString("IP", [string] $n.IP);
        $xmlWriter.WriteAttributeString("Prefix", [string] $n.Prefix);
        $xmlWriter.WriteAttributeString("InterfaceAlias", [string] $n.InterfaceAlias);
        $xmlWriter.WriteAttributeString("DHCP", [string] $n.DHCP);
        $xmlWriter.WriteEndElement() # NetIPAddress
    }
    $xmlWriter.WriteEndElement() # NetIPAddresses
}

function Collect-LocalUserAccounts {
    # using WMI to be compatible with older PS versions
    if (Get-Command CimInstance -ErrorAction SilentlyContinue) {
        $users = Get-CimInstance -class win32_useraccount -Filter "LocalAccount=True"
    } else {
        $users = Get-WmiObject -class win32_useraccount -Filter "LocalAccount=True"
    }
    return $users
}


function LocalUserAccounts-ToXML {

    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$users
        )

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
}


function Collect-LocalGroups {
    <#
    .SYNOPSIS
    Collects information about local groups on the system.

    .DESCRIPTION
    The Collect-LocalGroups function gathers details about local groups on the system, including their members. It
    uses WMI to query the groups and their associated members.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the local groups and their members.

    .EXAMPLE
    $groups = Collect-LocalGroups
    #>
    if (Get-Command CimInstance -ErrorAction SilentlyContinue) {
        $groups = Get-CimInstance -class win32_group -Filter "LocalAccount=True"
    } else {
        $groups = Get-WmiObject -class win32_group -Filter "LocalAccount=True"
    }
    try {
        foreach ($g in $groups ) {
            $groupname = [string] $g.Name
            $query="Associators of {Win32_Group.Domain='$hostname',Name='$groupname'} where Role=GroupComponent"
            $members = get-wmiobject -query $query -ComputerName $hostname
            $member_objects = New-Object System.Collections.ArrayList
            foreach ($m in $members){
                $member_objects.Add([PSCustomObject]@{
                    AccountType = [string] $m.AccountType;
                    Domain = [string] $m.Domain;
                    Name = [string] $m.Name;
                    SID = [string] $m.SID;
                    Caption = [string] $m.Caption;
                })
            }
            $g | Add-Member -MemberType NoteProperty -Name Members -Value $member_objects
        }
    } catch {}
    return $groups
}

function LocalGroups-ToXML {
    <#
    .SYNOPSIS
    Writes the local groups information to an XML file.

    .DESCRIPTION
    The LocalGroups-ToXML function writes the details of local groups and their members to an XML file. It takes an
    XML writer object and an array list of groups as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the local groups information to an XML file.

    .PARAMETER groups
    An array list containing the local groups and their members.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$groups
    )

    $xmlWriter.WriteStartElement("Groups")
    foreach ($g in $groups ) {
        $xmlWriter.WriteStartElement("Group")
        $xmlWriter.WriteElementString("Name",[string]$g.Name);
        $xmlWriter.WriteElementString("Caption", [string] $g.Caption);
        $xmlWriter.WriteElementString("Description",[string]$g.Description);
        $xmlWriter.WriteElementString("LocalAccount",[string]$g.LocalAccount);
        $xmlWriter.WriteElementString("SID",[string]$g.SID);
        $xmlWriter.WriteStartElement("Members")
        foreach ($m in $g.Members){
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
}

function Collect-FirewallInfo {
    <#
    .SYNOPSIS
    Collects information about the firewall status on the system.

    .DESCRIPTION
    The Collect-FirewallInfo function gathers information about the firewall status on the system, including the
    enabled profiles and their settings. It uses the Get-NetFirewallProfile cmdlet to query the firewall profiles.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the firewall profiles and their settings.

    .PARAMETER config_check_results (System.Collections.ArrayList)
    An array list containing the results of the configuration checks. The function adds a result object to this list

    .EXAMPLE
    $firewallInfo = Collect-FirewallInfo
    #>
    param (
        [System.Collections.ArrayList]$config_check_results
    )
    $firewallInfo = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($p in $profiles ) {
            $firewallInfo.Add([PSCustomObject]@{
                Name = [string] $p.Name;
                Enabled = [string] $p.Enabled;
            })
            if (!$p.Enabled){
                $result = [PSCustomObject]@{
                    Component = 'Firewall'
                    Name = 'FirewallEnabled'
                    Method       = 'Get-NetFirewallProfile'
                    Key   = $p.Name
                    Value      = $p.Enabled
                    Result = 'Firewall is not enabled for the profile'
                }
                $config_check_results.Add($result)
            }
        }
    }
    return $firewallInfo
}

function FirewallInfo-ToXML{
    <#
    .SYNOPSIS
    Writes the firewall status information to an XML file.

    .DESCRIPTION
    The FirewallStatus-ToXML function writes the details of the firewall status to an XML file. It takes an XML writer
    object and an array list of firewall profiles as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the firewall status information to an XML file.

    .PARAMETER firewallInfo
    An array list containing the firewall profiles and their settings.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$firewallInfo
    )

    $xmlWriter.WriteStartElement("NetFirewallProfiles")
    foreach ($f in $firewallInfo ) {
        $xmlWriter.WriteStartElement("FwProfile")
        $xmlWriter.WriteAttributeString("Name",[string] $f.Name);
        $xmlWriter.WriteAttributeString("Enabled",[string] $f.Enabled);
        $xmlWriter.WriteEndElement() # FwProfile
    }
    $xmlWriter.WriteEndElement() # NetFirewallProfiles
}


function Collect-Shares {
    <#
    .SYNOPSIS
    Collects information about shares on the system.

    .DESCRIPTION
    The Collect-Shares function gathers information about shares on the system, including their name, path, and
    permissions. It uses the Get-WmiObject cmdlet to query the shares and their permissions.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the shares and their permissions.

    .EXAMPLE
    $shares = Collect-Shares
    #>
    if (Get-Command CimInstance -ErrorAction SilentlyContinue) {
        $shares = Get-CimInstance -class win32_share
    } else {
        $shares = Get-WmiObject -class win32_share
    }
    $sharesInfo = New-Object System.Collections.ArrayList
    foreach ($s in $shares ) {
        $shareInfo = [PSCustomObject]@{
            Name = [string] $s.Name;
            Path = [string] $s.Path;
            Description = [string] $s.Description;
            NTFSPermissions = @()
            SharePermissions = @()
        }
        $path = [string] $s.Path
        try {
            $acl = get-acl -Path $path -ErrorAction SilentlyContinue
            foreach ($a in $acl.Access) {
                $shareInfo.NTFSPermissions += [PSCustomObject]@{
                    AccountName = [string] $a.IdentityReference;
                    AccessControlType = [string] $a.AccessControlType;
                    AccessRight = [string] $a.FileSystemRights;
                }
            }
        } catch {}
        if (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue) {
            try {
                $acl = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
                foreach ($a in $acl) {
                    $shareInfo.SharePermissions += [PSCustomObject]@{
                        ScopeName = [string] $a.ScopeName;
                        AccountName = [string] $a.AccountName;
                        AccessControlType = [string] $a.AccessControlType;
                        AccessRight = [string] $a.AccessRight;
                    }
                }
            } catch {}
        }else{
            try {
                $share = "\\" + $hostname  +"\"+  [string]$s.Name
                $acl = get-acl -Path $share -ErrorAction SilentlyContinue
                foreach ($a in $acl.Access) {
                    $shareInfo.SharePermissions += [PSCustomObject]@{
                        ScopeName = "";
                        AccountName = [string] $a.IdentityReference;
                        AccessControlType = [string] $a.AccessControlType;
                        AccessRight = [string] $a.FileSystemRights;
                    }
                }
            } catch {}
        }
        $sharesInfo.Add($shareInfo)
    }
    return $shares
}

function ShareInfo-ToXML{
    <#
    .SYNOPSIS
    Writes the share information to an XML file.

    .DESCRIPTION
    The ShareInfo-ToXML function writes the details of the shares and their permissions to an XML file. It takes an XML
    writer object and an array list of shares as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the share information to an XML file.

    .PARAMETER shares
    An array list containing the shares and their permissions.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$shares
    )

    $xmlWriter.WriteStartElement("Shares")
    foreach ($s in $shares ) {
        $xmlWriter.WriteStartElement("Share")
        $xmlWriter.WriteElementString("Name",[string] $s.Name);
        $xmlWriter.WriteElementString("Path",[string] $s.Path);
        $xmlWriter.WriteElementString("Description",[string] $s.Description);
        $xmlWriter.WriteStartElement("NTFSPermissions")
        foreach ($a in $s.NTFSPermissions) {
            $xmlWriter.WriteStartElement("Permission")
            $xmlWriter.WriteAttributeString("Name", [string] $s.Name);
            $xmlWriter.WriteAttributeString("AccountName", [string] $a.AccountName);
            $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType);
            $xmlWriter.WriteAttributeString("AccessRight", [string] $a.AccessRight);
            $xmlWriter.WriteEndElement() # Permission
        }
        $xmlWriter.WriteEndElement() # NTFSPermissions
        $xmlWriter.WriteStartElement("SharePermissions")
        foreach ($a in $s.SharePermissions) {
            $xmlWriter.WriteStartElement("Permission")
            $xmlWriter.WriteAttributeString("Name", [string] $s.Name);
            $xmlWriter.WriteAttributeString("ScopeName", [string] $a.ScopeName);
            $xmlWriter.WriteAttributeString("AccountName", [string] $a.AccountName);
            $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType);
            $xmlWriter.WriteAttributeString("AccessRight", [string] $a.AccessRight);
            $xmlWriter.WriteEndElement() # Permission
        }
        $xmlWriter.WriteEndElement() # SharePermissions
        $xmlWriter.WriteEndElement() # share
    }
    $xmlWriter.WriteEndElement() # shares
}

function Collect-WSUSSettings {
    <#
    .SYNOPSIS
    Collects WSUS settings from the registry.

    .DESCRIPTION
    The Collect-WSUSSettings function collects WSUS settings from the registry and returns them as a custom object.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the WSUS settings.

    .EXAMPLE
    $wsusSettings = Collect-WSUSSettings
    #>
    $wsusSettings = New-Object PSCustomObject
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "AcceptTrustedPublisherCerts") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name AcceptTrustedPublisherCerts -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name AcceptTrustedPublisherCerts -Value $wsus.AcceptTrustedPublisherCerts
    }
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "DisableWindowsUpdateAccess") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name DisableWindowsUpdateAccess -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name DisableWindowsUpdateAccess -Value $wsus.DisableWindowsUpdateAccess
    }
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "ElevateNonAdmins") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name ElevateNonAdmins -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name ElevateNonAdmins -Value $wsus.ElevateNonAdmins
    }
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "TargetGroup") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name TargetGroup -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name TargetGroup -Value $wsus.TargetGroup
    }
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "TargetGroup") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name TargetGroup -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name TargetGroup -Value $wsus.TargetGroup
    }
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "TargetGroupEnabled") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name TargetGroupEnabled -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name TargetGroupEnabled -Value $wsus.TargetGroupEnabled
    }
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "WUServer") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name WUServer -Value $wsus.WUServer
    }
    if ((get-item "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"  -ea SilentlyContinue).Property -contains "WUStatusServer") {
        $wsus =  Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name WUStatusServer -ErrorAction SilentlyContinue
        $wsusSettings | Add-Member -MemberType NoteProperty -Name WUStatusServer -Value $wsus.WUStatusServer
    }
}

function WSUSSettings-ToXML {
    <#
    .SYNOPSIS
    Writes the WSUS settings to an XML file.

    .DESCRIPTION
    The WSUSSettings-ToXML function writes the WSUS settings to an XML file. It takes an XML writer object and a custom
    object containing the WSUS settings as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the WSUS settings to an XML file.

    .PARAMETER wsusSettings
    A custom object containing the WSUS settings.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$wsusSettings
    )

    $xmlWriter.WriteStartElement("WSUS")
    if ($wsusSettings.PSObject.Properties.Name -contains "AcceptTrustedPublisherCerts") {
        $xmlWriter.WriteElementString("AcceptTrustedPublisherCerts", [string] $wsusSettings.AcceptTrustedPublisherCerts)
    }
    if ($wsusSettings.PSObject.Properties.Name -contains "DisableWindowsUpdateAccess") {
        $xmlWriter.WriteElementString("DisableWindowsUpdateAccess", [string] $wsusSettings.DisableWindowsUpdateAccess)
    }
    if ($wsusSettings.PSObject.Properties.Name -contains "ElevateNonAdmins") {
        $xmlWriter.WriteElementString("ElevateNonAdmins", [string] $wsusSettings.ElevateNonAdmins)
    }
    if ($wsusSettings.PSObject.Properties.Name -contains "TargetGroup") {
        $xmlWriter.WriteElementString("TargetGroup", [string] $wsusSettings.TargetGroup)
    }
    if ($wsusSettings.PSObject.Properties.Name -contains "TargetGroupEnabled") {
        $xmlWriter.WriteElementString("TargetGroupEnabled", [string] $wsusSettings.TargetGroupEnabled)
    }
    if ($wsusSettings.PSObject.Properties.Name -contains "WUServer") {
        $xmlWriter.WriteElementString("WUServer", [string] $wsusSettings.WUServer)
    }
    if ($wsusSettings.PSObject.Properties.Name -contains "WUStatusServer") {
        $xmlWriter.WriteElementString("WUStatusServer", [string] $wsusSettings.WUStatusServer)
    }
    $xmlWriter.WriteEndElement() # WSUS
}


function Collect-WinLogon {
    <#
    .SYNOPSIS
    Collects information about Winlogon settings.

    .DESCRIPTION
    The Collect-WinLogon function gathers information about Winlogon settings, including the autologon configuration.
    It uses the Get-ItemProperty cmdlet to query the registry for the settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the Winlogon settings.

    .EXAMPLE
    $winlogon = Collect-WinLogon
    #>
    param (
        [System.Collections.ArrayList]$config_checks
    )

    $winlogon = New-Object PSCustomObject
    if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultUserName") {
        $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue
        $winlogon | Add-Member -MemberType NoteProperty -Name DefaultUserName -Value $value.DefaultUserName
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
        $winlogon | Add-Member -MemberType NoteProperty -Name DefaultPassword -Value $defaultPassword
        $winlogon | Add-Member -MemberType NoteProperty -Name DefaultPasswordBase64 -Value $base64
        $winlogon | Add-Member -MemberType NoteProperty -Name DefaultPasswordEncrypted -Value $encrypted
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

        $winlogon | Add-Member -MemberType NoteProperty -Name DefaultPassword -Value $defaultPWObject
    }
    if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "AutoAdminLogon") {
        $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue
        $winlogon | Add-Member -MemberType NoteProperty -Name AutoAdminLogon -Value $value.AutoAdminLogon
    }
    if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "ForceAutoLogon") {
        $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ForceAutoLogon -ErrorAction SilentlyContinue
        $winlogon | Add-Member -MemberType NoteProperty -Name ForceAutoLogon -Value $value.ForceAutoLogon
    }
    if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"  -ea SilentlyContinue).Property -contains "DefaultDomainName") {
        $value =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue
        $winlogon | Add-Member -MemberType NoteProperty -Name DefaultDomain -Value $value.DefaultDomain
    }
}

function WinLogon-ToXML {
    <#
    .SYNOPSIS
    Writes the Winlogon settings to an XML file.

    .DESCRIPTION
    The WinLogon-ToXML function writes the details of the Winlogon settings to an XML file. It takes an XML writer object
    and a custom object containing the Winlogon settings as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the Winlogon settings to an XML file.

    .PARAMETER winlogon
    A custom object containing the Winlogon settings.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$winlogon
    )

    $xmlWriter.WriteStartElement("Winlogon")
    if ($winlogon.PSObject.Properties.Name -contains "DefaultUserName") {
        $xmlWriter.WriteElementString("DefaultUserName", [string] $winlogon.DefaultUserName)
    }
    if ($winlogon.PSObject.Properties.Name -contains "DefaultPassword") {
        $xmlWriter.WriteStartElement("DefaultPassword")
        if ($winlogon.PSObject.Properties.Name -contains "DefaultPasswordBase64") {
            $xmlWriter.WriteAttributeString("Base64", [string] $winlogon.DefaultPasswordBase64)
        }
        if ($winlogon.PSObject.Properties.Name -contains "DefaultPasswordEncrypted") {
            $xmlWriter.WriteAttributeString("Encrypted", [string] $winlogon.DefaultPasswordEncrypted)
        }
        $xmlWriter.WriteString([string] $winlogon.DefaultPassword)
        $xmlWriter.WriteEndElement() # DefaultPassword
    }
    if ($winlogon.PSObject.Properties.Name -contains "AutoAdminLogon") {
        $xmlWriter.WriteElementString("AutoAdminLogon", [string] $winlogon.AutoAdminLogon)
    }
    if ($winlogon.PSObject.Properties.Name -contains "ForceAutoLogon") {
        $xmlWriter.WriteElementString("ForceAutoLogon", [string] $winlogon.ForceAutoLogon)
    }
    if ($winlogon.PSObject.Properties.Name -contains "DefaultDomain") {
        $xmlWriter.WriteElementString("DefaultDomain", [string] $winlogon.DefaultDomain)
    }
    $xmlWriter.WriteEndElement() # Winlogon
}


function Collect-TlsSettings {
    param (
        [System.Collections.ArrayList]$config_checks
    )

    ###############################################################################################################
    # Check SSL / TLS settings
    # https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings?tabs=diffie-hellman
    ###############################################################################################################

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
}

function Collect-PSVersions {
    <#
    .SYNOPSIS
    Collects information about installed PowerShell versions.

    .DESCRIPTION
    The Collect-PSVersions function gathers information about installed PowerShell versions on the system. It uses the
    Get-ItemProperty cmdlet to query the registry for the installed versions.

    .PARAMETER config_checks (System.Collections.ArrayList)
    An array list containing the results of the configuration checks. The function adds a result object to this list.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the installed PowerShell versions.

    .EXAMPLE
    $psVersions = Collect-PSVersions -config_checks $config_checks_results
    #>
    param (
        [System.Collections.ArrayList]$config_checks,
        [PSCustomObject] $hostInfo
    )

    $psVersions = New-Object System.Collections.ArrayList
    $ids = (1..5)
    foreach ( $id in $ids) {
        $entry =  Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\$id\PowerShellEngine -ErrorAction SilentlyContinue
        if ($entry) {
            $psVersions.Add([PSCustomObject]@{
                PowerShellVersion = [string] $entry.PowerShellVersion;
                PSCompatibleVersion = [string] $entry.PSCompatibleVersion;
                PSPath = [string] $entry.PSPath;
                RuntimeVersion = [string] $entry.RuntimeVersion;
                ConsoleHostModuleName = [string] $entry.ConsoleHostModuleName;
            })
        }
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
    $hostInfo.PSVersion2Installed = $v2installed
    return $psVersions
}

function PSVersions-ToXML {
    <#
    .SYNOPSIS
    Writes the PowerShell versions to an XML file.

    .DESCRIPTION
    The PSVersions-ToXML function writes the details of the installed PowerShell versions to an XML file. It takes an
    XML writer object and an array list of PowerShell versions as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the PowerShell versions to an XML file.

    .PARAMETER psVersions
    An array list containing the installed PowerShell versions.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$psVersions
    )
    $v2installed = $false
    $xmlWriter.WriteStartElement("PSVersions")
    foreach ($p in $psVersions ) {
        $xmlWriter.WriteStartElement("PSVersion")
        $xmlWriter.WriteAttributeString("Version",[string] $p.PowerShellVersion);
        $xmlWriter.WriteAttributeString("PSCompatibleVersion",[string] $p.PSCompatibleVersion);
        $xmlWriter.WriteAttributeString("PSPath",[string] $p.PSPath);
        $xmlWriter.WriteAttributeString("RuntimeVersion",[string] $p.RuntimeVersion);
        $xmlWriter.WriteAttributeString("ConsoleHostModuleName",[string] $p.ConsoleHostModuleName);
        $xmlWriter.WriteEndElement() # PSVersion
    }
    $xmlWriter.WriteEndElement() # PSVersions
}
###################################################################################################################
#
###################################################################################################################

function Collect-WSHSettings {
    param (
        [System.Collections.ArrayList]$config_checks
    )
    $wsh_result =  New-Object PSCustomObject
    #######################################################################
    $wsh_trust_policy =""
    if ((get-item "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\"  -ea SilentlyContinue).Property -contains "TrustPolicy") {
        $wsh =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings\" -Name TrustPolicy -ErrorAction SilentlyContinue
        $wsh_trust_policy = [string] $wsh.TrustPolicy
    }else{
        $wsh_trust_policy = "N/A"
    }
    $wsh_result | Add-Member -MemberType NoteProperty -Name TrustPolicy -Value $wsh_trust_policy

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
    $wsh_result | Add-Member -MemberType NoteProperty -Name EnabledStatus -Value $wsh_enabled_status

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

    $wsh_result | Add-Member -MemberType NoteProperty -Name RemoteStatus -Value $wsh_remote_status

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
    return $wsh_result
}

function WSHSettings-ToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$wshSettings
    )

    $xmlWriter.WriteStartElement("WSH")
    if ($wshSettings.PSObject.Properties.Name -contains "TrustPolicy") {
        $xmlWriter.WriteElementString("TrustPolicy", [string] $wshSettings.TrustPolicy)
    }
    if ($wshSettings.PSObject.Properties.Name -contains "EnabledStatus") {
        $xmlWriter.WriteElementString("EnabledStatus", [string] $wshSettings.EnabledStatus)
    }
    if ($wshSettings.PSObject.Properties.Name -contains "RemoteStatus") {
        $xmlWriter.WriteElementString("RemoteStatus", [string] $wshSettings.RemoteStatus)
    }
    $xmlWriter.WriteEndElement() # WSH
}

function Check-LLMNR {
    <#
    .SYNOPSIS
    Checks if LLMNR is enabled.

    .DESCRIPTION
    The Check-LLMNR function checks if the Link-Local Multicast Name Resolution (LLMNR) protocol is enabled on the system.
    It uses the Get-ItemProperty cmdlet to query the registry for the LLMNR settings.

    .PARAMETER config_checks (System.Collections.ArrayList)
    An array list containing the results of the configuration checks. The function adds a result object to this list.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the LLMNR settings.

    .EXAMPLE
    $llmnr = Check-LLMNR
    #>
    param (
        [System.Collections.ArrayList]$config_checks
    )
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
}

function Check-SMBSigning{

    param (
        [System.Collections.ArrayList]$config_checks
    )

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
}





function Collect-NTPSettings {
    <#
    .SYNOPSIS
    Collects information about NTP settings.

    .DESCRIPTION
    The Collect-NTPSettings function gathers information about the NTP settings on the system. It uses the
    Get-ItemProperty cmdlet to query the registry for the NTP settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the NTP settings.

    .EXAMPLE
    $ntpSettings = Collect-NTPSettings
    #>
    $ntpSettings = New-Object PSCustomObject
    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "NtpServer") {
        $ntpServer =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name NtpServer -ErrorAction SilentlyContinue
        $ntpSettings | Add-Member -MemberType NoteProperty -Name Server -Value $ntpServer.NtpServer
    }
    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "Type") {
        $ntpType =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name Type -ErrorAction SilentlyContinue
        $ntpSettings | Add-Member -MemberType NoteProperty -Name NtpType -Value $ntpType.Type
    }
    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"  -ea SilentlyContinue).Property -contains "UpdateInterval") {
        $interval =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name UpdateInterval -ErrorAction SilentlyContinue
        $ntpSettings | Add-Member -MemberType NoteProperty -Name UpdateInterval -Value $interval.UpdateInterval
    }
    return $ntpSettings
}

function NTPSettings-ToXML {
    <#
    .SYNOPSIS
    Writes the NTP settings to an XML file.

    .DESCRIPTION
    The NTPSettings-ToXML function writes the details of the NTP settings to an XML file. It takes an XML writer object
    and a custom object containing the NTP settings as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the NTP settings to an XML file.

    .PARAMETER ntpSettings
    A custom object containing the NTP settings.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$ntpSettings
    )

    $xmlWriter.WriteStartElement("NTP")
    if ($ntpSettings.PSObject.Properties.Name -contains "NtpServer") {
        $xmlWriter.WriteElementString("Server", [string] $ntpSettings.Server)
    }
    if ($ntpSettings.PSObject.Properties.Name -contains "NtpType") {
        $xmlWriter.WriteElementString("Type", [string] $ntpSettings.NtpType)
    }
    if ($ntpSettings.PSObject.Properties.Name -contains "UpdateInterval") {
        $xmlWriter.WriteElementString("UpdateInterval", [string] $ntpSettings.UpdateInterval)
    }
    $xmlWriter.WriteEndElement() # NTP
}


function Collect-PSLogging {
    <#
    .SYNOPSIS
    Collects information about PowerShell logging settings.

    .DESCRIPTION
    The Collect-PSLogging function gathers information about the PowerShell logging settings on the system. It uses the
    Get-ItemProperty cmdlet to query the registry for the PowerShell logging settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the PowerShell logging settings.

    .EXAMPLE
    $psLogging = Collect-PSLogging
    #>
    $psLogging = New-Object PSCustomObject
    if ((get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"  -ea SilentlyContinue).Property -contains "EnableScriptBlockLogging") {
        $logging =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
        $psLogging | Add-Member -MemberType NoteProperty -Name ScriptBlockLogging -Value $logging.EnableScriptBlockLogging
    }
    return $psLogging
}


function PSLogging-ToXML {
    <#
    .SYNOPSIS
    Writes the PowerShell logging settings to an XML file.

    .DESCRIPTION
    The PSLogging-ToXML function writes the details of the PowerShell logging settings to an XML file. It takes an XML
    writer object and a custom object containing the PowerShell logging settings as input. The PSScriptBlockLogging Tag
    will be added to root element (Host).

    .PARAMETER xmlWriter
    An XML writer object used to write the PowerShell logging settings to an XML file.

    .PARAMETER psLogging
    A custom object containing the PowerShell logging settings.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$psLogging
    )

    if ($psLogging.PSObject.Properties.Name -contains "ScriptBlockLogging") {
        if ($logging -eq 1){
            $xmlWriter.WriteElementString("PSScriptBlockLogging", "Enabled")
        }else{
            $xmlWriter.WriteElementString("PSScriptBlockLogging", "Disabled")
        }
    }
}

function Collect-SMBConfig {
    <#
    .SYNOPSIS
    Collects information about the SMB configuration.

    .DESCRIPTION
    The Collect-SMBConfig function gathers information about the SMB configuration on the system. It uses the
    Get-SmbServerConfiguration cmdlet to query the SMB configuration. If Get-SmbServerConfiguration is not available,
    the function queries the registry for the SMB configuration.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the SMB configuration.

    .EXAMPLE
    $smbConfig = Collect-SMBConfig

    #>
    $smbConfig = New-Object PSCustomObject
    if (Get-Command Get-SmbServerConfiguration -ea SilentlyContinue) {
        # Cmdlet has been introduced in Windows 8, Windows Server 2012
        $smb = Get-SmbServerConfiguration
        $smbConfig | Add-Member -MemberType NoteProperty -Name SMB1Enabled -Value $smb.EnableSMB1Protocol
        $smbConfig | Add-Member -MemberType NoteProperty -Name SMB2Enabled -Value $smb.EnableSMB2Protocol
        $smbConfig | Add-Member -MemberType NoteProperty -Name EncryptData -Value $smb.EncryptData
        $smbConfig | Add-Member -MemberType NoteProperty -Name EnableSecuritySignature -Value $smb.EnableSecuritySignature
        $smbConfig | Add-Member -MemberType NoteProperty -Name RequireSecuritySignature -Value $smb.RequireSecuritySignature
    } else {
        # older Windows versions can check the registry.
        if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "SMB1") {
            $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -ErrorAction SilentlyContinue
            if ($smb1 -eq 0){
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB1Enabled -Value $false
            } else{
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB1Enabled -Value $true
            }
        } else {
            # Enabled by default. Since the entry does not exist it is enabled
            $smbConfig | Add-Member -MemberType NoteProperty -Name SMB1Enabled -Value $true
        }

        if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "SMB2") {
            $smb1 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -ErrorAction SilentlyContinue
            if ($smb1 -eq 0){
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB2Enabled -Value $false
            } else{
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB2Enabled -Value $true
            }
        } else {
            # Enabled by default. Since the entry does not exist it is enabled
            $smbConfig | Add-Member -MemberType NoteProperty -Name SMB2Enabled -Value $true
        }
    }
}

function SMBConfig-ToXML {
    <#
    .SYNOPSIS
    Writes the SMB configuration to an XML file.

    .DESCRIPTION
    The SMBConfig-ToXML function writes the details of the SMB configuration to an XML file. It takes an XML writer object
    and a custom object containing the SMB configuration as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the SMB configuration to an XML file.

    .PARAMETER smbConfig
    A custom object containing the SMB configuration.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$smbConfig
    )

    $xmlWriter.WriteStartElement("SMBSettings")
    if ($smbConfig.PSObject.Properties.Name -contains "SMB1Enabled") {
        $xmlWriter.WriteElementString("SMB1Enabled", [string] $smbConfig.SMB1Enabled)
    }
    if ($smbConfig.PSObject.Properties.Name -contains "SMB2Enabled") {
        $xmlWriter.WriteElementString("SMB2Enabled", [string] $smbConfig.SMB2Enabled)
    }
    if ($smbConfig.PSObject.Properties.Name -contains "EncryptData") {
        $xmlWriter.WriteElementString("EncryptData", [string] $smbConfig.EncryptData)
    }
    if ($smbConfig.PSObject.Properties.Name -contains "EnableSecuritySignature") {
        $xmlWriter.WriteElementString("EnableSecuritySignature", [string] $smbConfig.EnableSecuritySignature)
    }
    if ($smbConfig.PSObject.Properties.Name -contains "RequireSecuritySignature") {
        $xmlWriter.WriteElementString("RequireSecuritySignature", [string] $smbConfig.RequireSecuritySignature)
    }
    $xmlWriter.WriteEndElement() # SMBSettings
}

function Collect-DefenderInfo {
    <#
    .SYNOPSIS
    Collects information about Windows Defender settings.

    .DESCRIPTION
    The Collect-DefenderInfo function gathers information about Windows Defender settings on the system. It uses
    the Get-MpComputerStatus and Get-MpPreference cmdlets to query the Windows Defender settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the Windows Defender settings.

    .EXAMPLE
    $defenderInfo = Collect-DefenderInfo
    #>
    $defenderInfo = New-Object PSCustomObject
    if (Get-Command Get-MpComputerStatus -ea SilentlyContinue) {
        $status = Get-MpComputerStatus
        $defenderInfo | Add-Member -MemberType NoteProperty -Name MpComputerStatus -Value $status
    }
    if (Get-Command Get-MpPreference -ea SilentlyContinue) {
        $preferences = Get-MpPreference
        $defenderInfo | Add-Member -MemberType NoteProperty -Name MpPreference -Value $preferences
    }
    return $defenderInfo
}

function DefenderInfo-ToXML {
    <#
    .SYNOPSIS
    Writes the Windows Defender settings to an XML file.

    .DESCRIPTION
    The DefenderInfo-ToXML function writes the details of the Windows Defender settings to an XML file. It takes an XML
    writer object and a custom object containing the Windows Defender settings as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the Windows Defender settings to an XML file.

    .PARAMETER defenderInfo
    A custom object containing the Windows Defender settings.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$defenderInfo
    )

    $xmlWriter.WriteStartElement("Defender")
    if ($defenderInfo.PSObject.Properties.Name -contains "MpComputerStatus") {
        $status = $defenderInfo.MpComputerStatus
        $xmlWriter.WriteStartElement("DefenderStatus")
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
    if ($defenderInfo.PSObject.Properties.Name -contains "MpPreference") {
        $xmlWriter.WriteStartElement("Defender")
        $preferences = $defenderInfo.MpPreference
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
}

function Printers-ToXML {
    <#
    .SYNOPSIS
    Writes the printer information to an XML file.

    .DESCRIPTION
    The Printers-ToXML function writes the details of the printer information to an XML file. It takes an XML writer
    object and an array list of printers as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the printer information to an XML file.

    .PARAMETER printers
    An array list containing the printer information.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$printers
    )

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
}


function Collect-AclPathChecks {
    <#
    .SYNOPSIS
    Collects information about ACL checks for specified paths.

    .DESCRIPTION
    The Collect-AclPathChecks function gathers information about ACL checks for specified paths on the system. It uses
    the Get-Acl cmdlet to query the ACL settings for the specified paths.

    .PARAMETER acl_path_checks
    An array list containing the paths for which ACL checks should be performed.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the ACL checks for specified paths.

    .EXAMPLE
    $aclPathChecks = Collect-AclPathChecks
    #>
    param (
        [System.Collections.ArrayList]$acl_path_checks
    )
    $results = New-Object System.Collections.ArrayList
    foreach ($c in $acl_path_checks) {
        $path = [string] $c
        if (Test-Path $path) {
            $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
            $result = New-Object PSCustomObject
            $result | Add-Member -MemberType NoteProperty -Name Path -Value $path
            $result | Add-Member -MemberType NoteProperty -Name ACLs -Value $acl.Access
            $results.Add($result) | Out-Null
        }
    }
    return $results
}

function AclPathChecks-ToXML {
    <#
    .SYNOPSIS
    Writes the ACL checks for specified paths to an XML file.

    .DESCRIPTION
    The AclPathChecks-ToXML function writes the details of the ACL checks for specified paths to an XML file. It takes
    an XML writer object and an array list of ACL checks as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the ACL checks for specified paths to an XML file.

    .PARAMETER aclPathChecks
    An array list containing the ACL checks for specified paths.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$aclPathChecks
    )

    $xmlWriter.WriteStartElement("PathACLChecks")
    foreach ($c in $aclPathChecks) {
        $xmlWriter.WriteStartElement("PathACL")
        $xmlWriter.WriteElementString("Path", [string] $c.Path)
        $xmlWriter.WriteStartElement("ACLs")
        foreach ($a in $c.ACLs) {
            $xmlWriter.WriteStartElement("ACL")
            $xmlWriter.WriteAttributeString("path", [string] $c.Path);
            $xmlWriter.WriteAttributeString("AccountName", [string] $a.IdentityReference)
            $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType)
            $xmlWriter.WriteAttributeString("AccessRight", [string] $a.FileSystemRights)
            $xmlWriter.WriteEndElement() # ACL
        }
        $xmlWriter.WriteEndElement() # ACLs
        $xmlWriter.WriteEndElement() # PathACL
    }
    $xmlWriter.WriteEndElement() # PathACLChecks
}

function ConfigChecks-ToXML {
    <#
    .SYNOPSIS
    Writes the configuration checks to an XML file.

    .DESCRIPTION
    The ConfigChecks-ToXML function writes the details of the configuration checks to an XML file. It takes an XML writer
    object and an array list of configuration checks as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the configuration checks to an XML file.

    .PARAMETER configChecks
    An array list containing the configuration checks.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$configChecks
    )
    try{
        $xmlWriter.WriteStartElement("ConfigChecks")
        foreach ($c in $configChecks) {
            $xmlWriter.WriteStartElement("ConfigCheck")
            $xmlWriter.WriteElementString("Component", [string] $c.Component)
            $xmlWriter.WriteElementString("Name", [string] $c.Name)
            $xmlWriter.WriteElementString("Method", [string] $c.Method)
            $xmlWriter.WriteElementString("Key", [string] $c.Key)
            $xmlWriter.WriteElementString("Value", [string] $c.Value)
            $xmlWriter.WriteElementString("Result", [string] $c.Result)
            $xmlWriter.WriteElementString("Message", [string] $c.Message)
            $xmlWriter.WriteEndElement() # ConfigCheck
        }
        $xmlWriter.WriteEndElement() # ConfigChecks
    }catch {
        Write-Host "[-] Config Checks could not be written to XML"
    }

}


###############################################################################################################
# Collecting general computer information
###############################################################################################################
Write-Host "[*] Collecting general computer infos."

$hostInfo = Collect-HostInfo

# Adding Hostname and infos from parameters to hostInfo object
$hostInfo.Hostname = $hostname
$hostInfo.SystemGroup = $Systemgroup
$hostInfo.Location = $Location
$hostInfo.Label = $Label

###############################################################################################################
# Collecting BIOS information
###############################################################################################################
Write-Host "[*] Collecting BIOS information"
$biosInfo = Collect-BIOSInfo

###############################################################################################################
# Collecting information about installed hotfixes / patches
###############################################################################################################
Write-Host "[*] Collecting installed hotfixes"
$hotfixes = Collect-Hotfixes -host_info $hostInfo

###############################################################################################################
# Collecting information about installed products / applications
###############################################################################################################
Write-Host "[*] Collecting installed products"
$products = Collect-InstalledProducts

###############################################################################################################
# Collecting information about network adapters
###############################################################################################################
Write-Host "[*] Collecting available network adapters"
$netadapters = Collect-NetAdapter

###############################################################################################################
# Collecting information about IP addresses
###############################################################################################################
Write-Host "[*] Collecting IP addresses"
$netips = Collect-NetIPAddress

###############################################################################################################
# Collecting information about available routes (routing table)
###############################################################################################################
Write-Host "[*] Collecting routing table"
$routes = Collect-NetRoute

###############################################################################################################
# Collecting information about local user accounts
###############################################################################################################
Write-Host "[*] Collecting local user accounts"
$users = Collect-LocalUserAccounts

###############################################################################################################
# Collecting information about local groups
###############################################################################################################
Write-Host "[*] Collecting local groups"
$groups = Collect-LocalGroups

###############################################################################################################
# Perform: File Existence Checks
# This will check if specified files exist on the system and if they are matching a predefined hash.
# The matching of HASH is only performed in recent PowerShell versions by using Get-FileHash
###############################################################################################################
Write-Host "[*] Checking for existence of specified files"
$file_checks_results = Collect-FileExistCheck -FileChecks $file_checks

###############################################################################################################
# Collecting information about firewall status
###############################################################################################################
Write-Host "[*] Collecting firewall status"
$firewallInfo = Collect-FirewallInfo -config_check_results $config_check_results

###############################################################################################################
# Perform: Additional checks for entries in Windows Registry
#######################################################################
Write-Host "[*] Checking additional entries in Windows Registry"
$registry_check_results = Collect-RegistryChecks -RegistryChecks $registry_checks

###############################################################################################################
# Collecting Share information
#######################################################################
Write-Host "[*] Collecting information about shares"
$shares = Collect-Shares -ErrorAction SilentlyContinue

###############################################################################################################
# Collecting WSUS Settings in Registry
###############################################################################################################
Write-Host "[*] Checking WSUS configuration"
$wsusSettings = Collect-WSUSSettings

###############################################################################################################
# Collecting autologon settings
###############################################################################################################
Write-Host "[*] Checking autologon settings"
$winlogon = Collect-WinLogon -config_checks $config_check_results


###############################################################################################################
# Collecting SSL / TLS settings
##############################################################################################################
Write-Host "[*] Checking SSL/TLS settings"
Collect-TlsSettings -config_checks $config_check_results


###############################################################################################################
# Collecting PS Versions
##############################################################################################################
Write-Host "[*] Checking PS Versions"
$psVersions = Collect-PSVersions -config_checks $config_check_results -hostInfo $hostInfo

###############################################################################################################
# Collecting WSH Settings
##############################################################################################################
Write-Host "[*] Checking WSH settings"
$wshSettings = Collect-WSHSettings -config_checks $config_check_results

###############################################################################################################
# Check if LLMNR is enabled
###############################################################################################################
Write-Host "[*] Checking if LLMNR is enabled"
Check-LLMNR -config_checks $config_check_results

###############################################################################################################
# Check if SMB Signing is required
# https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview
###############################################################################################################
Write-Host "[*] Checking if SMB Signing is enabled"
Check-SMBSigning -config_checks $config_check_results


###############################################################################################################
# Collecting information about NTP configuration
###############################################################################################################
Write-Host "[*] Checking NTP configuration"
$ntpSettings = Collect-NTPSettings

###############################################################################################################
# Collecting information about PowerShell (PS Logging enabled ?)
###############################################################################################################

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
Write-Host "[*] Checking PS Logging is enabled"
$psLogging = Collect-PSLogging

###############################################################################################################
# Collecting information about SMB (Check if SMBv1 is enabled)
###############################################################################################################
Write-Host "[*] Checking if SMBv1 is enabled"
$smbConfig = Collect-SMBConfig


###############################################################################################################
# Collecting information about Defender (Status / Settings)
###############################################################################################################
Write-Host "[*] Checking Defender settings"
$defenderInfo = Collect-DefenderInfo


###############################################################################################################
# Collecting information about Printer
###############################################################################################################
Write-Host "[*] Checking if printers are installed"
$printers = New-Object System.Collections.ArrayList
if (Get-Command Get-Printer -ea SilentlyContinue) {
    try {
        $printers = Get-Printer -ea SilentlyContinue
    }catch{}
}

###############################################################################################################
# Perform: Path ACL Checks
###############################################################################################################
Write-Host "[*] Checking ACLs for specified pathes"
$aclPathChecks = Collect-AclPathChecks -acl_path_checks $acl_path_checks

###############################################################################################################
# Writing collected information to XML file
###############################################################################################################
$xmlfile = $path.Path + "\" + $date + "_SystemInfoCollector_"+$version+"_" + $hostname + ".xml"

try {
    $settings =  New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.IndentChars = $(" "*4)
    $xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
    $xmlWriter.WriteStartDocument()
        $xmlWriter.WriteStartElement("SystemInfoCollector")
            $xmlWriter.WriteAttributeString("version", "$version")
            $xmlWriter.WriteStartElement("Host")
                try {
                    HostInfo-ToXML -xmlWriter $xmlWriter -hostInfo $hostInfo
                } catch { Write-host "[-] HostInfo could not be written to XML" }
                try {
                    BIOSInfo-ToXML -xmlWriter $xmlWriter -biosInfo $biosInfo
                } catch { Write-host "[-] BIOSInfo could not be written to XML" }
                try {
                    Hotfixes-ToXML -xmlWriter $xmlWriter -hotfixes $hotfixes
                } catch { Write-host "[-] Hotfixes could not be written to XML" }
                try {
                    InstalledProducts-ToXML -xmlWriter $xmlWriter -products $products
                } catch { Write-host "[-] InstalledProducts could not be written to XML" }
                try {
                    NetAdapter-ToXML -xmlWriter $xmlWriter -netadapters $netadapter
                } catch { Write-host "[-] NetAdapter could not be written to XML" }
                try {
                    NetRoute-ToXML -xmlWriter $xmlWriter -routes $routes
                } catch { Write-host "[-] NetRoute could not be written to XML" }
                try {
                    NetIPAddress-ToXML -xmlWriter $xmlWriter -netips $netips
                } catch { Write-host "[-] NetIPAddress could not be written to XML" }
                try {
                    LocalUserAccounts-ToXML -xmlWriter $xmlWriter -users $users
                } catch { Write-host "[-] LocalUserAccounts could not be written to XML" }
                try {
                    LocalGroups-ToXML -xmlWriter $xmlWriter -groups $groups
                } catch { Write-host "[-] LocalGroups could not be written to XML" }
                try {
                    FileExistChecksToXML -xmlWriter $xmlWriter -file_checks_results $file_checks_results
                } catch { Write-host "[-] FileExistChecks could not be written to XML" }
                try {
                    FirewallInfo-ToXML -xmlWriter $xmlWriter -firewallInfo $firewallInfo
                } catch { Write-host "[-] FirewallInfo could not be written to XML" }
                try {
                    RegistryChecksToXML -xmlWriter $xmlWriter -registry_check_results $registry_check_results
                } catch { Write-host "[-] RegistryChecks could not be written to XML" }
                try {
                    SharesInfo-ToXML -xmlWriter $xmlWriter -shares $shares
                } catch { Write-host "[-] SharesInfo could not be written to XML" }
                try {
                    WSUSSettings-ToXML -xmlWriter $xmlWriter -wsusSettings $wsusSettings
                } catch { Write-host "[-] WSUSSettings could not be written to XML" }
                try {
                    Winlogon-ToXML -xmlWriter $xmlWriter -winlogon $winlogon
                } catch { Write-host "[-] Winlogon could not be written to XML" }
                try {
                    PSVersions-ToXML -xmlWriter $xmlWriter -psVersions $psVersions
                } catch { Write-host "[-] PSVersions could not be written to XML" }
                try {
                    WSHSettings-ToXML -xmlWriter $xmlWriter -wshSettings $wshSettings
                } catch { Write-host "[-] WSHSettings could not be written to XML" }
                try {
                    NTPSettings-ToXML -xmlWriter $xmlWriter -ntpSettings $ntpSettings
                } catch { Write-host "[-] NTPSettings could not be written to XML" }
                try {
                    PSLogging-ToXML -xmlWriter $xmlWriter -psLogging $psLogging
                } catch { Write-host "[-] PSLogging could not be written to XML" }
                try {
                    SMBConfig-ToXML -xmlWriter $xmlWriter -smbConfig $smbConfig
                } catch { Write-host "[-] SMBConfig could not be written to XML" }
                try {
                    DefenderInfo-ToXML -xmlWriter $xmlWriter -defenderInfo $defenderInfo
                } catch { Write-host "[-] DefenderInfo could not be written to XML" }
                try {
                    Printers-ToXML -xmlWriter $xmlWriter -printers $printers
                } catch { Write-host "[-] Printers could not be written to XML" }
                try {
                    AclPathChecks-ToXML -xmlWriter $xmlWriter -aclPathChecks $aclPathChecks
                } catch { Write-host "[-] AclPathChecks could not be written to XML" }
                try {
                    ConfigChecks-ToXML -xmlWriter $xmlWriter -config_check_results $config_check_results
                } catch { Write-host "[-] ConfigChecks could not be written to XML" }
            $xmlWriter.WriteEndElement() # Host
        $xmlWriter.WriteEndElement() # SystemInfoCollector
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()
}catch {
    Write-Host "[-] XML file could not be written"
    Write-Host "[*] Exporting to CSV file"

    # TODO:  Export to CSV
}



