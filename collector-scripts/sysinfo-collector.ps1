<#
    .SYNOPSIS
    This PowerShell script is to fetch system information.

    .DESCRIPTION
    This PowerShell script is to fetch system information. The collector script is published as part of "REVEAL".
    https://github.com/c-bless/reveal

    Author:     Christoph Bless (github@cbless.de)
    Version:    0.7
    License:    GPLv3

    .INPUTS
    None

    .OUTPUTS
    This script will create a XML-file (default), a JSON-file or both with the collected system information
    (see parameter -OutputFormat). Both formats contain the same information.

    .EXAMPLE
    .\sysinfo-collector.ps1

    .Example
    .\sysinfo-collector.ps1 -Systemgroup PCS7 -Location "Control room" -Label "Inventory Number"

    .EXAMPLE
    .\sysinfo-collector.ps1 -OutputFormat Both
    Writes the collected information to a XML file and to a JSON file.

    .EXAMPLE
    .\sysinfo-collector.ps1 -OutputFormat JSON
    Writes the collected information only to a JSON file.

    .EXAMPLE
    .\sysinfo-collector.ps1 -UseWin32Product
    Collects the installed products via Win32_Product instead of the registry (slow, only MSI packages, triggers a
    Windows Installer consistency check for every MSI package).
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
    [string]$Label = "N/A",

    # output format: XML (default), JSON or Both
    [Parameter(Mandatory=$false)]
    [ValidateSet('XML', 'JSON', 'Both')]
    [string]$OutputFormat = 'XML',

    # collect installed products via Win32_Product instead of the Uninstall keys in the registry. Win32_Product is
    # very slow, only returns MSI packages and causes Windows Installer to run a consistency check (and possibly a
    # repair) for every MSI package (Event-ID 1035 / 1040).
    [Parameter(Mandatory=$false)]
    [switch]$UseWin32Product
)


# version number of this script used as attribute in XML root tag
$version="0.7"

$date = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname = $env:COMPUTERNAME

# can be generated with helper script ./genkey.py
[byte[]] $encKey = (7, 16, 166, 10, 141, 23, 37, 94, 240, 162, 206, 168, 181, 97, 19, 170)

$path = Get-Location

# check only once whether CIM cmdlets are available (instead of in every function). Get-CimInstance is available
# since PowerShell 3.0, Get-WmiObject is not available anymore in PowerShell 6+.
$script:UseCim = [bool](Get-Command Get-CimInstance -ErrorAction SilentlyContinue)
$script:UseWmi = [bool](Get-Command Get-WmiObject -ErrorAction SilentlyContinue)

function Get-WmiData {
    <#
    .SYNOPSIS
    Queries a WMI class via Get-CimInstance (if available) or Get-WmiObject.

    .PARAMETER Class
    Name of the WMI class (e.g. Win32_Service)

    .PARAMETER Filter
    Optional WQL filter (e.g. "LocalAccount=True")
    #>
    param (
        [Parameter(Mandatory=$true)][string]$Class,
        [string]$Filter
    )
    $params = @{ ErrorAction = 'Stop' }
    if ($Filter) { $params.Filter = $Filter }
    try {
        if ($script:UseCim) { return Get-CimInstance -ClassName $Class @params }
        if ($script:UseWmi) { return Get-WmiObject -Class $Class @params }
    } catch {
        # Write-Host instead of Write-Output: the message must not become part of the return value
        Write-Host "[-] $Class could not be queried: $($_.Exception.Message)"
    }
    return $null
}


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
function Get-RegistryChecks {
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
    return ,$registry_check_results
}


function Add-RegistryChecksToXML{
    <#
    .SYNOPSIS
    This function writes the results of the registry checks to an XML file.
    .DESCRIPTION
    The Add-RegistryChecksToXML function is designed to write the results of the registry checks to an XML file. It takes
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

function Get-FileExistCheck {
    <#
    .SYNOPSIS
    This function checks if a file exists and if the hash of the file matches the expected hash.
    .DESCRIPTION
    The Get-FileExistCheck function is designed to check if a file exists and if the hash of the file matches the
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
                # Write-Host instead of Write-Output: otherwise the message becomes part of the return value
                Write-Host "[!] Found file: $path"
                $result.FileExist = $true
                if (Get-Command Get-FileHash -ErrorAction SilentlyContinue){
                    $expectedHash = [string] $c.ExpectedHASH
                    $hash = Get-FileHash -Path $path -Algorithm SHA256
                    $result.HashChecked = $true
                    if ($expectedHash -eq $hash.HASH){
                        $result.HashMatch = $true
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
    return ,$file_checks_results
}


function Add-FileExistChecksToXML{
    <#
    .SYNOPSIS
    This function writes the results of the file existence checks to an XML file.
    .DESCRIPTION
    The Add-FileExistChecksToXML function is designed to write the results of the file existence checks to an XML file. It
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


function Get-HostInfo {
    <#
    .SYNOPSIS
    Collects general information about the host system.

    .DESCRIPTION
    The Get-HostInfo function gathers various details about the host system, such as OS version, domain information,
    and user details. It uses the Get-ComputerInfo cmdlet if available, otherwise, it falls back to WMI queries for
    older PowerShell versions.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the collected host information.

    .EXAMPLE
    $hostInfo = Get-HostInfo
    #>
    $host_info = [PSCustomObject]@{}
    if (Get-Command Get-ComputerInfo -ErrorAction SilentlyContinue){
        $compInfo = Get-ComputerInfo

        $osversion = ""
        if ([string]::IsNullOrEmpty($compInfo.OSVersion)){
            try{
                $osversion = [string] $compInfo.WindowsVersion
            }catch{}
        }else{
                $osversion = [string] $compInfo.OSVersion
        }
        $osname = ""

        if ([string]::IsNullOrEmpty($compInfo.OSName)){
            try{
                $osname = [string] $compInfo.WindowsProductName
            }catch{}
        }else{
            $osname = [string] $compInfo.OSName
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
            Manufacturer = [string] $compInfo.CsManufacturer
            Model = [string] $compInfo.CsModel
            PrimaryOwnerName = [string] $compInfo.CsPrimaryOwnerName
            Whoami = [string] [System.Environment]::UserName
            WhoamiIsAdmin = [string] ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            PSVersion = [string]$PSVersionTable.PSVersion
            PSVersion2Installed = ""
            LastUpdate = [string] "N/A"
        }
    }else{
        $domain = [string] [System.Environment]::UserDomainName
        $domainRole = ""
        $hypervisor = ""
        $installDate = ""
        $manufacturer = ""
        $model = ""
        $PrimaryOwnerName = ""
        $osversion = ""
        $osname = ""
        $osProductType = ""
        $timezoneString = ""
        try{
            $cs = Get-WmiData -Class Win32_ComputerSystem
            $domainRoles = @('StandaloneWorkstation', 'MemberWorkstation', 'StandaloneServer', 'MemberServer',
                             'BackupDomainController', 'PrimaryDomainController')
            $role = [int] $cs.DomainRole
            if ($role -ge 0 -and $role -lt $domainRoles.Count) { $domainRole = $domainRoles[$role] } else { $domainRole = [string] $cs.DomainRole }
            if ($cs.Domain) { $domain = [string] $cs.Domain }
            $hypervisor = [string]$cs.HypervisorPresent
            $manufacturer = [string] $cs.Manufacturer
            $model = [string] $cs.Model
            $PrimaryOwnerName = [string] $cs.PrimaryOwnerName
        } catch{}
        try{
            $os = Get-WmiData -Class Win32_OperatingSystem
            $osversion = [string] $os.Version
            $osname = [string] $os.Caption
            # WMI returns a DMTF string (Get-WmiObject), CIM a DateTime
            $osInstall = $os.InstallDate
            if ($osInstall -is [string]) {
                try { $osInstall = [System.Management.ManagementDateTimeConverter]::ToDateTime($osInstall) } catch {}
            }
            $installDate = [string] $osInstall
            $productTypes = @{ 1 = 'WorkStation'; 2 = 'DomainController'; 3 = 'Server' }
            $pt = [int] $os.ProductType
            if ($productTypes.ContainsKey($pt)) { $osProductType = $productTypes[$pt] } else { $osProductType = [string] $os.ProductType }
        } catch{}
        try {
            $timezone = Get-WmiData -Class Win32_TimeZone
            $timezoneString = [string] $timezone.Caption
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
            OSProductType = $osProductType
            LogonServer = [string] $env:LOGONSERVER
            TimeZone = $timezoneString
            KeyboardLayout = ""
            HyperVisorPresent = $hypervisor
            DeviceGuardSmartStatus = ""
            Manufacturer = $manufacturer
            Model = $model
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

function Add-HostInfoToXML {
    <#
    .SYNOPSIS
    Writes the host information to an XML file.
    .DESCRIPTION
    The Add-HostInfoToXML function is designed to write the host information to an XML file. It takes a custom object
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
    $xmlWriter.WriteElementString("CollectionDate",[string] $hostInfo.CollectionDate)
    $xmlWriter.WriteElementString("Domain",[string] $hostInfo.Domain)
    $xmlWriter.WriteElementString("DomainRole",[string] $hostInfo.DomainRole)
    $xmlWriter.WriteElementString("OSBuildNumber",[string] $hostInfo.OSBuildNumber)
    $xmlWriter.WriteElementString("OSVersion",[string] $hostInfo.OSVersion)
    $xmlWriter.WriteElementString("OSName", [string] $hostInfo.OSName)
    $xmlWriter.WriteElementString("OSInstallDate",[string] $hostInfo.OSInstallDate)
    $xmlWriter.WriteElementString("OSProductType",[string] $hostInfo.OSProductType)
    $xmlWriter.WriteElementString("LogonServer", [string] $hostInfo.LogonServer)
    $xmlWriter.WriteElementString("TimeZone",[string]$hostInfo.TimeZone)
    $xmlWriter.WriteElementString("KeyboardLayout",[string]$hostInfo.KeyboardLayout)
    $xmlWriter.WriteElementString("HyperVisorPresent",[string]$hostInfo.HyperVisorPresent)
    $xmlWriter.WriteElementString("DeviceGuardSmartStatus",[string]$hostInfo.DeviceGuardSmartStatus)
    $xmlWriter.WriteElementString("PrimaryOwnerName",[string] $hostInfo.PrimaryOwnerName)
    $xmlWriter.WriteElementString("Manufacturer",[string] $hostInfo.Manufacturer)
    $xmlWriter.WriteElementString("Model",[string] $hostInfo.Model)
    $xmlWriter.WriteElementString("Whoami", [string] $hostInfo.Whoami)
    $xmlWriter.WriteElementString("WhoamiIsAdmin", [string] $hostInfo.WhoamiIsAdmin)
    $xmlWriter.WriteElementString("PSVersion",[string]$hostInfo.PSVersion)
    $xmlWriter.WriteElementString("PSVersion2Installed",[string]$hostInfo.PSVersion2Installed)
    $xmlWriter.WriteElementString("LastUpdate",[string] $hostInfo.LastUpdate)
}



###################################################################################################################
# Functions collect and export BIOS information
###################################################################################################################
function Get-BIOSInfo {
    <#
    .SYNOPSIS
    Collects BIOS information from the host system.
    .DESCRIPTION
    The Get-BIOSInfo function gathers information about the BIOS of the host system, such as the manufacturer,
    version, and serial number. It queries the Win32_BIOS class (CIM or WMI) for this information.
    .OUTPUTS
    [PSCustomObject]
    A custom object containing the collected BIOS information.
    #>
    $bios = Get-WmiData -Class Win32_BIOS
    $biosInfo = [PSCustomObject]@{
        Manufacturer = [string] $bios.Manufacturer
        Name = [string] $bios.Name
        Version = [string] $bios.Version
        SerialNumber = [string] $bios.SerialNumber
    }
    return $biosInfo
}

function Add-BIOSInfoToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [PSCustomObject]$biosInfo
    )

    $xmlWriter.WriteStartElement("BIOS")
    $xmlWriter.WriteAttributeString("Manufacturer", [string] $biosInfo.Manufacturer)
    $xmlWriter.WriteAttributeString("Name", [string] $biosInfo.Name)
    $xmlWriter.WriteAttributeString("Version", [string] $biosInfo.Version)
    $xmlWriter.WriteAttributeString("SerialNumber", [string] $biosInfo.SerialNumber)
    # the REVEAL importer reads the attribute "Serial"
    $xmlWriter.WriteAttributeString("Serial", [string] $biosInfo.SerialNumber)
    $xmlWriter.WriteEndElement() # BIOS
}


function Get-HotfixesInfo {

    param (
        [PSCustomObject]$host_info
    )
    
    $hotfix_list = New-Object System.Collections.ArrayList
    $collectionMethod = ""

    $hotfixes = @()
    if (Get-Command Get-HotFix -ErrorAction SilentlyContinue){
        $collectionMethod = "Get-HotFix"
        try { $hotfixes = @(Get-HotFix -ErrorAction Stop) } catch {}
    }
    if ($hotfixes.Count -eq 0) {
        if ($script:UseCim) { $collectionMethod = "CIM" } else { $collectionMethod = "WMI" }
        try { $hotfixes = @(Get-WmiData -Class Win32_QuickFixEngineering) } catch {}
    }
    try{
        $hotfixes = @($hotfixes | Sort-Object -Property InstalledOn -Descending -ErrorAction Stop)
    } catch {}
    # most recent installation date (entries without InstalledOn are skipped)
    $lastUpdate = $hotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
    if ($lastUpdate) {
        $host_info.LastUpdate = [string] $lastUpdate.InstalledOn
    }

    foreach ($h in $hotfixes){
        $hotfix = [PSCustomObject]@{
            CollectionMethod = $collectionMethod
            id = [string] $h.HotFixID
            InstalledOn = [string] $h.InstalledOn
            Description = [string] $h.Description
        }
        [void] $hotfix_list.Add($hotfix)
    }

    return ,$hotfix_list
}


function Add-HotfixesToXML {

    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$hotfixes,
        [PSCustomObject]$hostInfo
    )


    $xmlWriter.WriteStartElement("Hotfixes")
    # the REVEAL importer reads the date of the last update from this attribute
    $xmlWriter.WriteAttributeString("LastUpdate", [string] $hostInfo.LastUpdate)
    foreach ($h in $hotfixes ) {
        $xmlWriter.WriteStartElement("Hotfix")
        $xmlWriter.WriteAttributeString("id",  [string] $h.id)
        $xmlWriter.WriteAttributeString("InstalledOn",[string] $h.InstalledOn)
        $xmlWriter.WriteAttributeString("Description",[string] $h.Description)
        $xmlWriter.WriteEndElement() # hotfix
    }
    $xmlWriter.WriteEndElement() # hotfixes
}


function Get-UninstallEntries {
    <#
    .SYNOPSIS
    Reads the products below one Uninstall key of the registry.

    .DESCRIPTION
    Entries are skipped in the same way as in "Apps & Features": entries without DisplayName, system components
    (SystemComponent = 1) and updates / patches (ParentKeyName or ReleaseType Update, Hotfix, Security Update).
    Errors in single entries are ignored, the remaining entries are still collected.

    .PARAMETER BaseKey
    Opened registry base key (e.g. HKLM in the 64-bit or 32-bit view, or HKEY_USERS)

    .PARAMETER SubKey
    Path of the Uninstall key below the base key

    .PARAMETER Architecture
    Architecture of the registry view (x64 / x86). Empty for per user installations.

    .PARAMETER Scope
    "Machine" for installations for all users, otherwise the SID of the user
    #>
    param (
        [Microsoft.Win32.RegistryKey]$BaseKey,
        [string]$SubKey,
        [string]$Architecture,
        [string]$Scope
    )
    $entries = New-Object System.Collections.ArrayList
    $uninstallKey = $null
    try { $uninstallKey = $BaseKey.OpenSubKey($SubKey) } catch {}
    if (-not $uninstallKey) { return ,$entries }
    try {
        foreach ($name in $uninstallKey.GetSubKeyNames()) {
            $key = $null
            try {
                $key = $uninstallKey.OpenSubKey($name)
                if (-not $key) { continue }
                $displayName = [string] $key.GetValue('DisplayName')
                if ([string]::IsNullOrEmpty($displayName)) { continue }
                if ([string] $key.GetValue('SystemComponent') -eq '1') { continue }
                if ($key.GetValue('ParentKeyName')) { continue }
                if (@('Update', 'Hotfix', 'Security Update') -contains [string] $key.GetValue('ReleaseType')) { continue }
                [void] $entries.Add([PSCustomObject]@{
                    IdentifyingNumber = [string] $name
                    Name = $displayName
                    Caption = $displayName
                    InstallDate = [string] $key.GetValue('InstallDate')
                    Description = [string] $key.GetValue('Comments')
                    Vendor = [string] $key.GetValue('Publisher')
                    Version = [string] $key.GetValue('DisplayVersion')
                    InstallLocation = [string] $key.GetValue('InstallLocation')
                    Architecture = $Architecture
                    Scope = $Scope
                    CollectionMethod = "Registry"
                })
            } catch {
                # ignore broken entries, continue with the next one
            } finally {
                if ($key) { $key.Close() }
            }
        }
    } finally {
        $uninstallKey.Close()
    }
    return ,$entries
}


function Get-InstalledProductsInfo {
    <#
    .SYNOPSIS
    Collects the installed products.

    .DESCRIPTION
    By default the products are read from the Uninstall keys of the registry (same source as "Apps & Features"):
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall              (64-bit view, all users)
      - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall  (32-bit view, all users)
      - HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Uninstall          (per user, loaded profiles only)
    Reading the registry is read-only, fast and also covers products that have not been installed via MSI.
    The 64-bit and 32-bit views are opened explicitly, so the 64-bit products are also found if the script runs in a
    32-bit PowerShell on a 64-bit system (registry redirection). Products of users that are not logged on are not
    collected (their registry hive is not loaded).

    With -UseWin32Product the Win32_Product class is used instead (slow, only MSI packages, triggers a Windows
    Installer consistency check for every MSI package).

    .PARAMETER UseWin32Product
    Use Win32_Product instead of the registry.

    .OUTPUTS
    [System.Collections.ArrayList] of products
    #>
    param (
        [switch]$UseWin32Product
    )
    $product_list = New-Object System.Collections.ArrayList

    if ($UseWin32Product) {
        $method = if ($script:UseCim) { "CIM" } else { "WMI" }
        foreach ($p in @(Get-WmiData -Class Win32_Product)) {
            try {
                [void] $product_list.Add([PSCustomObject]@{
                    IdentifyingNumber = [string] $p.IdentifyingNumber
                    Name = [string] $p.Name
                    Caption = [string] $p.Caption
                    InstallDate = [string] $p.InstallDate
                    Description = [string] $p.Description
                    Vendor = [string] $p.Vendor
                    Version = [string] $p.Version
                    InstallLocation = [string] $p.InstallLocation
                    Architecture = ""
                    Scope = "Machine"
                    CollectionMethod = $method
                })
            } catch {}
        }
        return ,$product_list
    }

    $uninstallPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $sources = New-Object System.Collections.ArrayList

    # installations for all users (64-bit and 32-bit view of HKLM)
    try {
        if ([Environment]::Is64BitOperatingSystem) {
            $views = @(@{ View = [Microsoft.Win32.RegistryView]::Registry64; Arch = 'x64' },
                       @{ View = [Microsoft.Win32.RegistryView]::Registry32; Arch = 'x86' })
        } else {
            $views = @(@{ View = [Microsoft.Win32.RegistryView]::Default; Arch = 'x86' })
        }
        foreach ($v in $views) {
            $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $v.View)
            [void] $sources.Add(@{ Base = $hklm; SubKey = $uninstallPath; Arch = $v.Arch; Scope = 'Machine' })
        }
    } catch {
        Write-Host "[-] Registry of the local machine could not be opened: $($_.Exception.Message)"
    }

    # per user installations of the loaded user profiles (S-1-5-21-...: local and domain accounts, without *_Classes)
    try {
        $users = [Microsoft.Win32.Registry]::Users
        foreach ($sid in $users.GetSubKeyNames()) {
            if ($sid -match '^S-1-5-21-[\d-]+$') {
                [void] $sources.Add(@{ Base = $users; SubKey = "$sid\$uninstallPath"; Arch = ''; Scope = $sid })
            }
        }
    } catch {}

    # the same product can be registered more than once (e.g. MSI package and setup bootstrapper)
    $seen = @{}
    foreach ($src in $sources) {
        foreach ($e in (Get-UninstallEntries -BaseKey $src.Base -SubKey $src.SubKey -Architecture $src.Arch -Scope $src.Scope)) {
            $id = "{0}|{1}|{2}|{3}" -f $e.Name, $e.Version, $e.Architecture, $e.Scope
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            [void] $product_list.Add($e)
        }
    }
    foreach ($src in $sources) {
        if ($src.Scope -eq 'Machine') { try { $src.Base.Close() } catch {} }
    }
    return ,$product_list
}


function Add-InstalledProductsToXML {

    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$products
    )

    # all product objects are created by Get-InstalledProductsInfo and have the same properties
    $xmlWriter.WriteStartElement("Products")
    foreach ($p in $products ) {
        try{
            $xmlWriter.WriteStartElement("Product")
            $xmlWriter.WriteElementString("Caption", [string] $p.Caption)
            $xmlWriter.WriteElementString("InstallDate", [string] $p.InstallDate)
            $xmlWriter.WriteElementString("Description", [string] $p.Description)
            $xmlWriter.WriteElementString("Vendor", [string] $p.Vendor)
            $xmlWriter.WriteElementString("Name", [string] $p.Name)
            $xmlWriter.WriteElementString("Version", [string] $p.Version)
            $xmlWriter.WriteElementString("InstallLocation", [string] $p.InstallLocation)
            $xmlWriter.WriteEndElement() # product
        }catch{}
    }
    $xmlWriter.WriteEndElement() # products
}



function Get-NetAdapterInfo {
   $result_list = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
        $netadapters = Get-NetAdapter
        # Add an alias property to the object to make it compatible with the get-wmiobject object
        foreach ($n in $netadapters ) {
            $n = [PSCustomObject]@{
                CollectionMethod = "Get-NetAdapter"
                Type = "N/A"
                MacAddress = [string] $n.MacAddress
                Status = [string] $n.Status
                Name = [string] $n.Name
                InterfaceDescription = [string] $n.InterfaceDescription
            }
            #$n | Add-Member -MemberType NoteProperty -Name Type -Value "N/A" -Force
            [void]$result_list.add($n)
        }
    }else{
        try {
            $netadapters = Get-WmiData -Class Win32_NetworkAdapter
            # create objects with the same properties as the Get-NetAdapter objects
            foreach ($n in $netadapters ) {
                $n = [PSCustomObject]@{
                    CollectionMethod = $(if ($script:UseCim) { "CIM" } else { "WMI" })
                    Type = [string] $n.AdapterType
                    MacAddress = [string] $n.MacAddress
                    Status = [string] $n.Status
                    Name = [string] $n.Name
                    InterfaceDescription = [string] $n.Description
                }
                [void]$result_list.add($n)
            }
        } catch {}
    }
    return ,$result_list
}


function Add-NetAdapterToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$netadapters
    )

    $xmlWriter.WriteStartElement("Netadapters")
    foreach ($n in $netadapters ) {
        $xmlWriter.WriteStartElement("Netadapter")
        $xmlWriter.WriteAttributeString("MacAddress", [string] $n.MacAddress)
        try {
            $xmlWriter.WriteAttributeString("Type",[string] $n.Type)
        } catch {}
        $xmlWriter.WriteAttributeString("Status",[string] $n.Status)
        $xmlWriter.WriteAttributeString("Name",[string] $n.Name)
        $xmlWriter.WriteAttributeString("InterfaceDescription",[string] $n.InterfaceDescription)
        $xmlWriter.WriteEndElement() # netadapter
    }
    $xmlWriter.WriteEndElement() # netadapters
}


function Get-NetRouteInfo {
    $route_list =  New-Object System.Collections.ArrayList

    if (Get-Command Get-NetRoute -ErrorAction SilentlyContinue) {
        $routes = Get-NetRoute
    }else{
        $routes = New-Object System.Collections.ArrayList
    }
    foreach ($r in $routes) {
        $route = [PSCustomObject]@{
            AddressFamily = [string] $r.AddressFamily
            DestinationPrefix = [string]$r.DestinationPrefix
            InterfaceAlias = [string]$r.InterfaceAlias
            NextHop =[string]$r.NextHop
            RouteMetric = [string]$r.RouteMetric
            IfIndex = [string]$r.ifIndex
            InterfaceMetric = [string]$r.InterfaceMetric
            IsStatic = [string]$r.IsStatic
            AdminDistance = [string]$r.AdminDistance
        }
        [void] $route_list.Add($route)
    }
    return ,$route_list
}

function Add-NetRouteToXML {

    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$routes
    )

    $xmlWriter.WriteStartElement("Routes")
    foreach ($r in $routes ) {
        $xmlWriter.WriteStartElement("Route")
        $xmlWriter.WriteElementString("AddressFamily", [string] $r.AddressFamily)
        $xmlWriter.WriteElementString("DestinationPrefix", [string]$r.DestinationPrefix)
        $xmlWriter.WriteElementString("InterfaceAlias", [string]$r.InterfaceAlias)
        $xmlWriter.WriteElementString("NextHop", [string]$r.NextHop)
        $xmlWriter.WriteElementString("RouteMetric", [string]$r.RouteMetric)
        # the REVEAL importer reads "IfIndex"
        $xmlWriter.WriteElementString("IfIndex", [string]$r.IfIndex)
        $xmlWriter.WriteElementString("InterfaceMetric", [string]$r.InterfaceMetric)
        $xmlWriter.WriteElementString("IsStatic", [string]$r.IsStatic)
        $xmlWriter.WriteElementString("AdminDistance", [string]$r.AdminDistance)
        $xmlWriter.WriteEndElement() # Route
    }
    $xmlWriter.WriteEndElement() # Routes

}

function Get-NetIPAddressInfo {
    $netips = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue ) {
        $netipaddresses = Get-NetIPAddress
        foreach ($n in $netipaddresses ) {
            [void]$netips.Add([PSCustomObject]@{
                AddressFamily = [string] $n.AddressFamily
                Type = [string] $n.Type
                IP = [string] $n.IPAddress
                Prefix = [string] $n.PrefixLength
                InterfaceAlias = [string] $n.InterfaceAlias
                DHCP = [string] ""
            })
        }
    } else {
        try{
            $netadapters = Get-WmiData -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 'True'"
            foreach ($n in $netadapters ) {
                foreach ($i in $n.IPAddress){
                    [void]$netips.Add([PSCustomObject]@{
                        AddressFamily = [string] ""
                        Type = [string] ""
                        IP = [string] $i
                        Prefix = [string] ""
                        InterfaceAlias = [string] $n.Caption
                        DHCP = [string] $n.DHCPEnabled
                    })
                }
            }
        }catch{}
    }
    return ,$netips
}

function Add-NetIPAddressToXML {
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$netips
    )

    $xmlWriter.WriteStartElement("NetIPAddresses")
    foreach ($n in $netips ) {
        $xmlWriter.WriteStartElement("NetIPAddress")
        $xmlWriter.WriteAttributeString("AddressFamily", [string] $n.AddressFamily)
        $xmlWriter.WriteAttributeString("Type", [string] $n.Type)
        $xmlWriter.WriteAttributeString("IP", [string] $n.IP)
        $xmlWriter.WriteAttributeString("Prefix", [string] $n.Prefix)
        $xmlWriter.WriteAttributeString("InterfaceAlias", [string] $n.InterfaceAlias)
        $xmlWriter.WriteAttributeString("DHCP", [string] $n.DHCP)
        $xmlWriter.WriteEndElement() # NetIPAddress
    }
    $xmlWriter.WriteEndElement() # NetIPAddresses
}

function Get-LocalUserAccountsInfo {
    $user_list = New-Object System.Collections.ArrayList
    $users = Get-WmiData -Class Win32_UserAccount -Filter "LocalAccount=True"
    foreach ($u in $users ) {
        $user = [PSCustomObject]@{  
            AccountType = [string] $u.AccountType
            Domain = [string]$u.Domain
            Disabled = [string]$u.Disabled
            LocalAccount = [string]$u.LocalAccount
            Name = [string]$u.Name
            FullName = [string]$u.FullName
            Description = [string]$u.Description
            SID = [string]$u.SID
            Lockout = [string]$u.Lockout
            PasswordChangeable = [string]$u.PasswordChangeable
            PasswordExpires = [string]$u.PasswordExpires
            PasswordRequired = [string]$u.PasswordRequired
        }
        [void] $user_list.Add($user)
    }
    return ,$user_list
}


function Add-LocalUserAccountsToXML {

    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$users
    )

    $xmlWriter.WriteStartElement("Users")
    foreach ($u in $users ) {
        $xmlWriter.WriteStartElement("User")
        $xmlWriter.WriteElementString("AccountType", [string] $u.AccountType)
        $xmlWriter.WriteElementString("Domain", [string]$u.Domain)
        $xmlWriter.WriteElementString("Disabled",[string]$u.Disabled)
        $xmlWriter.WriteElementString("LocalAccount",[string]$u.LocalAccount)
        $xmlWriter.WriteElementString("Name",[string]$u.Name)
        $xmlWriter.WriteElementString("FullName",[string]$u.FullName)
        $xmlWriter.WriteElementString("Description",[string]$u.Description)
        $xmlWriter.WriteElementString("SID",[string]$u.SID)
        $xmlWriter.WriteElementString("Lockout",[string]$u.Lockout)
        $xmlWriter.WriteElementString("PasswordChangeable",[string]$u.PasswordChangeable)
        $xmlWriter.WriteElementString("PasswordExpires",[string]$u.PasswordExpires)
        $xmlWriter.WriteElementString("PasswordRequired",[string]$u.PasswordRequired)
        $xmlWriter.WriteEndElement() # user
    }
    $xmlWriter.WriteEndElement() # users
}


function Get-LocalGroupsInfo {
    <#
    .SYNOPSIS
    Collects information about local groups on the system.

    .DESCRIPTION
    The Get-LocalGroups function gathers details about local groups on the system, including their members. It
    uses WMI to query the groups and their associated members.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the local groups and their members.

    .EXAMPLE
    $groups = Get-LocalGroups
    #>
    $group_list = New-Object System.Collections.ArrayList
    $groups = Get-WmiData -Class Win32_Group -Filter "LocalAccount=True"
    try {
        foreach ($g in $groups ) {
            $groupname = [string] $g.Name
            $members = @()
            try {
                if ($script:UseCim) {
                    $members = @(Get-CimAssociatedInstance -InputObject $g -Association Win32_GroupUser -ErrorAction Stop)
                } else {
                    $query="Associators of {Win32_Group.Domain='$($g.Domain)',Name='$groupname'} where AssocClass=Win32_GroupUser Role=GroupComponent"
                    $members = @(Get-WmiObject -Query $query -ErrorAction Stop)
                }
            } catch {}
            $member_objects = New-Object System.Collections.ArrayList
            foreach ($m in $members){
                [void] $member_objects.Add([PSCustomObject]@{
                    AccountType = [string] $m.AccountType
                    Domain = [string] $m.Domain
                    Name = [string] $m.Name
                    SID = [string] $m.SID
                    Caption = [string] $m.Caption
                })
            }
            $group = [PSCustomObject]@{
                Name = $groupname
                Caption = [string] $g.Caption
                Description = [string]$g.Description
                LocalAccount = [string]$g.LocalAccount
                SID = [string]$g.SID
                Members =  $member_objects
            }
            # $g | Add-Member -MemberType NoteProperty -Name Members -Value $member_objects
            [void] $group_list.Add($group)
        }
    } catch {}
    return ,$group_list
}

function Add-LocalGroupsToXML {
    <#
    .SYNOPSIS
    Writes the local groups information to an XML file.

    .DESCRIPTION
    The Add-LocalGroupsToXML function writes the details of local groups and their members to an XML file. It takes an
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
        $xmlWriter.WriteElementString("Name",[string]$g.Name)
        $xmlWriter.WriteElementString("Caption", [string] $g.Caption)
        $xmlWriter.WriteElementString("Description",[string]$g.Description)
        $xmlWriter.WriteElementString("LocalAccount",[string]$g.LocalAccount)
        $xmlWriter.WriteElementString("SID",[string]$g.SID)
        $xmlWriter.WriteStartElement("Members")
        foreach ($m in $g.Members){
            $xmlWriter.WriteStartElement("Member")
            $xmlWriter.WriteElementString("AccountType", [string] $m.AccountType)
            $xmlWriter.WriteElementString("Domain", [string] $m.Domain)
            $xmlWriter.WriteElementString("Name", [string] $m.Name)
            $xmlWriter.WriteElementString("SID", [string] $m.SID)
            $xmlWriter.WriteElementString("Caption", [string] $m.Caption)
            $xmlWriter.WriteEndElement()
        }
        $xmlWriter.WriteEndElement() #Members
        $xmlWriter.WriteEndElement() # group
    }
    $xmlWriter.WriteEndElement() # groups
}

function Get-FirewallInfo {
    <#
    .SYNOPSIS
    Collects information about the firewall status on the system.

    .DESCRIPTION
    The Get-FirewallInfo function gathers information about the firewall status on the system, including the
    enabled profiles and their settings. It uses the Get-NetFirewallProfile cmdlet to query the firewall profiles.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the firewall profiles and their settings.

    .PARAMETER config_check_results (System.Collections.ArrayList)
    An array list containing the results of the configuration checks. The function adds a result object to this list

    .EXAMPLE
    $firewallInfo = Get-FirewallInfo
    #>
    param (
        [System.Collections.ArrayList]$config_check_results
    )
    $firewallInfo = New-Object System.Collections.ArrayList
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($p in $profiles ) {
            [void]$firewallInfo.Add([PSCustomObject]@{
                Name = [string] $p.Name
                Enabled = [string] $p.Enabled
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
                [void]$config_check_results.Add($result)
            }
        }
    }
    return ,$firewallInfo
}

function Add-FirewallInfoToXML{
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
        $xmlWriter.WriteAttributeString("Name",[string] $f.Name)
        $xmlWriter.WriteAttributeString("Enabled",[string] $f.Enabled)
        $xmlWriter.WriteEndElement() # FwProfile
    }
    $xmlWriter.WriteEndElement() # NetFirewallProfiles
}


function Get-SharesInfo {
    <#
    .SYNOPSIS
    Collects information about shares on the system.

    .DESCRIPTION
    The Get-Shares function gathers information about shares on the system, including their name, path, and
    permissions. It queries the Win32_Share class (CIM or WMI) and the permissions of the shares.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the shares and their permissions.

    .EXAMPLE
    $shares = Get-Shares
    #>
    $shares = Get-WmiData -Class Win32_Share
    $sharesInfo_results = New-Object System.Collections.ArrayList
    foreach ($s in $shares ) {
        $shareInfo = [PSCustomObject]@{
            Name = [string] $s.Name
            Path = [string] $s.Path
            Description = [string] $s.Description
            NTFSPermissions = New-Object System.Collections.ArrayList
            SharePermissions = New-Object System.Collections.ArrayList
        }
        $path = [string] $s.Path
        try {
            $acl = get-acl -Path $path -ErrorAction SilentlyContinue
            foreach ($a in $acl.Access) {
                $perm = [PSCustomObject]@{
                    AccountName = [string] $a.IdentityReference
                    AccessControlType = [string] $a.AccessControlType
                    AccessRight = [string] $a.FileSystemRights
                }
                [void]$shareInfo.NTFSPermissions.Add($perm)
            }
        } catch {}
        if (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue) {
            try {
                $acl = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
                foreach ($a in $acl) {
                    $perm = [PSCustomObject]@{
                        ScopeName = [string] $a.ScopeName
                        AccountName = [string] $a.AccountName
                        AccessControlType = [string] $a.AccessControlType
                        AccessRight = [string] $a.AccessRight
                    }
                    [void]$shareInfo.SharePermissions.Add($perm)
                }
            } catch {}
        }else{
            try {
                $share = "\\" + $hostname  +"\"+  [string]$s.Name
                $acl = get-acl -Path $share -ErrorAction SilentlyContinue
                foreach ($a in $acl.Access) {
                    $perm = [PSCustomObject]@{
                        ScopeName = ""
                        AccountName = [string] $a.IdentityReference
                        AccessControlType = [string] $a.AccessControlType
                        AccessRight = [string] $a.FileSystemRights
                    }
                    [void]$shareInfo.SharePermissions.Add($perm)
                }
            } catch {}
        }
        [void]$sharesInfo_results.Add($shareInfo)
    }
    return ,$sharesInfo_results
}

function Add-ShareInfoToXML{
    <#
    .SYNOPSIS
    Writes the share information to an XML file.

    .DESCRIPTION
    The Add-ShareInfoToXML function writes the details of the shares and their permissions to an XML file. It takes an XML
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
        $xmlWriter.WriteElementString("Name",[string] $s.Name)
        $xmlWriter.WriteElementString("Path",[string] $s.Path)
        $xmlWriter.WriteElementString("Description",[string] $s.Description)
        $xmlWriter.WriteStartElement("NTFSPermissions")
        if ($s.PSObject.Properties.Name -contains "NTFSPermissions") {
            foreach ($a in $s.NTFSPermissions) {
                $xmlWriter.WriteStartElement("Permission")
                $xmlWriter.WriteAttributeString("Name", [string] $s.Name)
                $xmlWriter.WriteAttributeString("AccountName", [string] $a.AccountName)
                $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType)
                $xmlWriter.WriteAttributeString("AccessRight", [string] $a.AccessRight)
                $xmlWriter.WriteEndElement() # Permission
            }
        }
        $xmlWriter.WriteEndElement() # NTFSPermissions
        $xmlWriter.WriteStartElement("SharePermissions")
        if ($s.PSObject.Properties.Name -contains "SharePermissions") {
            foreach ($a in $s.SharePermissions) {
                $xmlWriter.WriteStartElement("Permission")
                $xmlWriter.WriteAttributeString("Name", [string] $s.Name)
                $xmlWriter.WriteAttributeString("ScopeName", [string] $a.ScopeName)
                $xmlWriter.WriteAttributeString("AccountName", [string] $a.AccountName)
                $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType)
                $xmlWriter.WriteAttributeString("AccessRight", [string] $a.AccessRight)
                $xmlWriter.WriteEndElement() # Permission
            }
        }
        $xmlWriter.WriteEndElement() # SharePermissions
        $xmlWriter.WriteEndElement() # share
    }
    $xmlWriter.WriteEndElement() # shares
}

function Get-WSUSSettings {
    <#
    .SYNOPSIS
    Collects WSUS settings from the registry.

    .DESCRIPTION
    The Get-WSUSSettings function collects WSUS settings from the registry and returns them as a custom object.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the WSUS settings.

    .EXAMPLE
    $wsusSettings = Get-WSUSSettings
    #>
    $wsusSettings = [PSCustomObject]@{}
    $wsusKey = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $wsus = Get-ItemProperty -Path $wsusKey -ErrorAction SilentlyContinue
    if ($wsus) {
        foreach ($name in @('AcceptTrustedPublisherCerts', 'DisableWindowsUpdateAccess', 'ElevateNonAdmins', 'TargetGroup',
                            'TargetGroupEnabled', 'WUServer', 'WUStatusServer')) {
            if ($wsus.PSObject.Properties.Name -contains $name) {
                $wsusSettings | Add-Member -MemberType NoteProperty -Name $name -Value $wsus.$name
            }
        }
    }
    return $wsusSettings
}

function Add-WSUSSettingsToXML {
    <#
    .SYNOPSIS
    Writes the WSUS settings to an XML file.

    .DESCRIPTION
    The Add-WSUSSettingsToXML function writes the WSUS settings to an XML file. It takes an XML writer object and a custom
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


function Get-WinLogonInfo {
    <#
    .SYNOPSIS
    Collects information about Winlogon settings.

    .DESCRIPTION
    The Get-WinLogon function gathers information about Winlogon settings, including the autologon configuration.
    It uses the Get-ItemProperty cmdlet to query the registry for the settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the Winlogon settings.

    .EXAMPLE
    $winlogon = Get-WinLogon
    #>
    param (
        [System.Collections.ArrayList]$config_checks
    )

    $winlogon = [PSCustomObject]@{}
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
            # KeySize is derived from the key (16 bytes -> AES-128), matching IMPORT_KEY of REVEAL
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
        $winlogon | Add-Member -MemberType NoteProperty -Name DefaultDomainName -Value $value.DefaultDomainName
    }
    return $winlogon
}

function Add-WinLogonToXML {
    <#
    .SYNOPSIS
    Writes the Winlogon settings to an XML file.

    .DESCRIPTION
    The Add-WinLogonToXML function writes the details of the Winlogon settings to an XML file. It takes an XML writer object
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
        # the REVEAL importer reads the lower case attributes "base64" and "encrypted" (XML is case sensitive)
        if ($winlogon.PSObject.Properties.Name -contains "DefaultPasswordBase64") {
            $xmlWriter.WriteAttributeString("base64", [string] $winlogon.DefaultPasswordBase64)
        }
        if ($winlogon.PSObject.Properties.Name -contains "DefaultPasswordEncrypted") {
            $xmlWriter.WriteAttributeString("encrypted", [string] $winlogon.DefaultPasswordEncrypted)
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
    # the REVEAL importer reads "DefaultDomainName"
    if ($winlogon.PSObject.Properties.Name -contains "DefaultDomainName") {
        $xmlWriter.WriteElementString("DefaultDomainName", [string] $winlogon.DefaultDomainName)
    }
    $xmlWriter.WriteEndElement() # Winlogon
}


function Test-TlsSettings {
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

function Get-PSVersionsInfo {
    <#
    .SYNOPSIS
    Collects information about installed PowerShell versions.

    .DESCRIPTION
    The Get-PSVersions function gathers information about installed PowerShell versions on the system. It uses the
    Get-ItemProperty cmdlet to query the registry for the installed versions.

    .PARAMETER config_checks (System.Collections.ArrayList)
    An array list containing the results of the configuration checks. The function adds a result object to this list.

    .OUTPUTS
    [System.Collections.ArrayList]
    An array list containing the installed PowerShell versions.

    .EXAMPLE
    $psVersions = Get-PSVersions -config_checks $config_checks_results
    #>
    param (
        [System.Collections.ArrayList]$config_checks,
        [PSCustomObject] $hostInfo
    )

    $psVersions = New-Object System.Collections.ArrayList
    $v2installed = $false
    $ids = (1..5)
    foreach ( $id in $ids) {
        $entry =  Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\$id\PowerShellEngine -ErrorAction SilentlyContinue
        if ($entry) {
            [void]$psVersions.Add([PSCustomObject]@{
                PowerShellVersion = [string] $entry.PowerShellVersion
                PSCompatibleVersion = [string] $entry.PSCompatibleVersion
                PSPath = [string] $entry.PSPath
                RuntimeVersion = [string] $entry.RuntimeVersion
                ConsoleHostModuleName = [string] $entry.ConsoleHostModuleName
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
    return ,$psVersions
}

function Add-PSVersionsToXML {
    <#
    .SYNOPSIS
    Writes the PowerShell versions to an XML file.

    .DESCRIPTION
    The Add-PSVersionsToXML function writes the details of the installed PowerShell versions to an XML file. It takes an
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
    $xmlWriter.WriteStartElement("PSVersions")
    foreach ($p in $psVersions ) {
        $xmlWriter.WriteStartElement("PSVersion")
        $xmlWriter.WriteAttributeString("Version",[string] $p.PowerShellVersion)
        # the REVEAL importer reads the attribute "PSVersion"
        $xmlWriter.WriteAttributeString("PSVersion",[string] $p.PowerShellVersion)
        $xmlWriter.WriteAttributeString("PSCompatibleVersion",[string] $p.PSCompatibleVersion)
        $xmlWriter.WriteAttributeString("PSPath",[string] $p.PSPath)
        $xmlWriter.WriteAttributeString("RuntimeVersion",[string] $p.RuntimeVersion)
        $xmlWriter.WriteAttributeString("ConsoleHostModuleName",[string] $p.ConsoleHostModuleName)
        $xmlWriter.WriteEndElement() # PSVersion
    }
    $xmlWriter.WriteEndElement() # PSVersions
}
###################################################################################################################
#
###################################################################################################################

function Get-WSHSettings {
    param (
        [System.Collections.ArrayList]$config_checks
    )
    $wsh_result =  [PSCustomObject]@{}
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

function Add-WSHSettingsToXML {
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

function Test-LLMNR {
    <#
    .SYNOPSIS
    Checks if LLMNR is enabled.

    .DESCRIPTION
    The Test-LLMNR function checks if the Link-Local Multicast Name Resolution (LLMNR) protocol is enabled on the system.
    It uses the Get-ItemProperty cmdlet to query the registry for the LLMNR settings.

    .PARAMETER config_checks (System.Collections.ArrayList)
    An array list containing the results of the configuration checks. The function adds a result object to this list.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the LLMNR settings.

    .EXAMPLE
    $llmnr = Test-LLMNR
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

function Test-SMBSigning{

    param (
        [System.Collections.ArrayList]$config_checks
    )

    # check if "Microsoft network client: Digitally sign communications (always)" is required
    $client_sign_value = ""
    $client_sign_result = ""
    $client_sign_msg = ""
    if ((get-item "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  -ea SilentlyContinue).Property -contains "RequireSecuritySignature") {
        $cs =  Get-ItemProperty -Path  "HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"  -Name RequireSecuritySignature -ErrorAction SilentlyContinue
        $client_sign_value = $cs.RequireSecuritySignature
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
        $se =  Get-ItemProperty -Path  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"  -Name RequireSecuritySignature -ErrorAction SilentlyContinue
        $srv_sign_value = $se.RequireSecuritySignature
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





function Get-NTPSettings {
    <#
    .SYNOPSIS
    Collects information about NTP settings.

    .DESCRIPTION
    The Get-NTPSettings function gathers information about the NTP settings on the system. It uses the
    Get-ItemProperty cmdlet to query the registry for the NTP settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the NTP settings.

    .EXAMPLE
    $ntpSettings = Get-NTPSettings
    #>
    $ntpSettings = [PSCustomObject]@{}
    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "NtpServer") {
        $ntpServer =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name NtpServer -ErrorAction SilentlyContinue
        $ntpSettings | Add-Member -MemberType NoteProperty -Name Server -Value $ntpServer.NtpServer
    }
    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"  -ea SilentlyContinue).Property -contains "Type") {
        $ntpType =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name Type -ErrorAction SilentlyContinue
        $ntpSettings | Add-Member -MemberType NoteProperty -Name Type -Value $ntpType.Type
    }
    if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config"  -ea SilentlyContinue).Property -contains "UpdateInterval") {
        $interval =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name UpdateInterval -ErrorAction SilentlyContinue
        $ntpSettings | Add-Member -MemberType NoteProperty -Name UpdateInterval -Value $interval.UpdateInterval
    }
    return $ntpSettings
}

function Add-NTPSettings-ToXML {
    <#
    .SYNOPSIS
    Writes the NTP settings to an XML file.

    .DESCRIPTION
    The Add-NTPSettings-ToXML function writes the details of the NTP settings to an XML file. It takes an XML writer object
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
    if ($ntpSettings.PSObject.Properties.Name -contains "Server") {
        $xmlWriter.WriteElementString("Server", [string] $ntpSettings.Server)
    }
    if ($ntpSettings.PSObject.Properties.Name -contains "Type") {
        $xmlWriter.WriteElementString("Type", [string] $ntpSettings.Type)
    }
    if ($ntpSettings.PSObject.Properties.Name -contains "UpdateInterval") {
        $xmlWriter.WriteElementString("UpdateInterval", [string] $ntpSettings.UpdateInterval)
    }
    $xmlWriter.WriteEndElement() # NTP
}


function Get-PSLoggingInfo {
    <#
    .SYNOPSIS
    Collects information about PowerShell logging settings.

    .DESCRIPTION
    The Get-PSLogging function gathers information about the PowerShell logging settings on the system. It uses the
    Get-ItemProperty cmdlet to query the registry for the PowerShell logging settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the PowerShell logging settings.

    .EXAMPLE
    $psLogging = Get-PSLogging
    #>
    $psLogging = [PSCustomObject]@{}
    if ((get-item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"  -ea SilentlyContinue).Property -contains "EnableScriptBlockLogging") {
        $logging =  Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
        $psLogging | Add-Member -MemberType NoteProperty -Name ScriptBlockLogging -Value $logging.EnableScriptBlockLogging
        $state = if ($logging.EnableScriptBlockLogging -eq 1) { "Enabled" } else { "Disabled" }
        $psLogging | Add-Member -MemberType NoteProperty -Name PSScriptBlockLogging -Value $state
    }
    return $psLogging
}


function Add-PSLoggingToXML {
    <#
    .SYNOPSIS
    Writes the PowerShell logging settings to an XML file.

    .DESCRIPTION
    The Add-PSLoggingToXML function writes the details of the PowerShell logging settings to an XML file. It takes an XML
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

    if ($psLogging.PSObject.Properties.Name -contains "PSScriptBlockLogging") {
        $xmlWriter.WriteElementString("PSScriptBlockLogging", [string] $psLogging.PSScriptBlockLogging)
    }
}

function Get-SMBConfig {
    <#
    .SYNOPSIS
    Collects information about the SMB configuration.

    .DESCRIPTION
    The Get-SMBConfig function gathers information about the SMB configuration on the system. It uses the
    Get-SmbServerConfiguration cmdlet to query the SMB configuration. If Get-SmbServerConfiguration is not available,
    the function queries the registry for the SMB configuration.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the SMB configuration.

    .EXAMPLE
    $smbConfig = Get-SMBConfig

    #>
    $smbConfig = [PSCustomObject]@{}
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
            if ($smb1.SMB1 -eq 0){
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB1Enabled -Value $false
            } else{
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB1Enabled -Value $true
            }
        } else {
            # Enabled by default. Since the entry does not exist it is enabled
            $smbConfig | Add-Member -MemberType NoteProperty -Name SMB1Enabled -Value $true
        }

        if ((get-item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -ea SilentlyContinue).Property -contains "SMB2") {
            $smb2 =  Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -ErrorAction SilentlyContinue
            if ($smb2.SMB2 -eq 0){
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB2Enabled -Value $false
            } else{
                $smbConfig | Add-Member -MemberType NoteProperty -Name SMB2Enabled -Value $true
            }
        } else {
            # Enabled by default. Since the entry does not exist it is enabled
            $smbConfig | Add-Member -MemberType NoteProperty -Name SMB2Enabled -Value $true
        }
    }
    return $smbConfig
}

function Add-SMBConfigToXML {
    <#
    .SYNOPSIS
    Writes the SMB configuration to an XML file.

    .DESCRIPTION
    The Add-SMBConfigToXML function writes the details of the SMB configuration to an XML file. It takes an XML writer object
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

function Get-DefenderInfo {
    <#
    .SYNOPSIS
    Collects information about Windows Defender settings.

    .DESCRIPTION
    The Get-DefenderInfo function gathers information about Windows Defender settings on the system. It uses
    the Get-MpComputerStatus and Get-MpPreference cmdlets to query the Windows Defender settings.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the Windows Defender settings.

    .EXAMPLE
    $defenderInfo = Get-DefenderInfo
    #>
    $statusProperties = @('AMEngineVersion', 'AMProductVersion', 'AMServiceEnabled', 'AMServiceVersion',
        'AntispywareEnabled', 'AntispywareSignatureLastUpdated', 'AntispywareSignatureVersion', 'AntivirusEnabled',
        'AntivirusSignatureLastUpdated', 'AntivirusSignatureVersion', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled',
        'IsVirtualMachine', 'NISEnabled', 'NISEngineVersion', 'NISSignatureLastUpdated', 'NISSignatureVersion',
        'OnAccessProtectionEnabled', 'RealTimeProtectionEnabled')
    $preferenceProperties = @('DisableArchiveScanning', 'DisableAutoExclusions', 'DisableBehaviorMonitoring',
        'DisableBlockAtFirstSeen', 'DisableCatchupFullScan', 'DisableCatchupQuickScan', 'DisableEmailScanning',
        'DisableIntrusionPreventionSystem', 'DisableIOAVProtection', 'DisableRealtimeMonitoring',
        'DisableRemovableDriveScanning', 'DisableRestorePoint', 'DisableScanningMappedNetworkDrivesForFullScan',
        'DisableScanningNetworkFiles', 'DisableScriptScanning', 'EnableNetworkProtection', 'ExclusionPath',
        'ExclusionProcess')

    # The raw CIM objects are converted to plain objects with string values. This way the JSON export contains
    # exactly the values written to the XML file (and not the complete CIM object).
    $defenderInfo = [PSCustomObject]@{}
    if (Get-Command Get-MpComputerStatus -ea SilentlyContinue) {
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            $obj = [ordered]@{}
            foreach ($n in $statusProperties) { $obj[$n] = [string] $status.$n }
            $defenderInfo | Add-Member -MemberType NoteProperty -Name MpComputerStatus -Value ([PSCustomObject]$obj)
        } catch {}
    }
    if (Get-Command Get-MpPreference -ea SilentlyContinue) {
        try {
            $preferences = Get-MpPreference -ErrorAction Stop
            $obj = [ordered]@{}
            foreach ($n in $preferenceProperties) { $obj[$n] = [string] $preferences.$n }
            $defenderInfo | Add-Member -MemberType NoteProperty -Name MpPreference -Value ([PSCustomObject]$obj)
        } catch {}
    }
    return $defenderInfo
}

function Add-DefenderInfoToXML {
    <#
    .SYNOPSIS
    Writes the Windows Defender settings to an XML file.

    .DESCRIPTION
    The Add-DefenderInfoToXML function writes the details of the Windows Defender settings to an XML file. It takes an XML
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

    # DefenderStatus and Defender (settings) are written as separate child elements of Host - this is the structure
    # the REVEAL importer expects.
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
        $xmlWriter.WriteEndElement() # DefenderStatus
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

function Add-PrintersToXML {
    <#
    .SYNOPSIS
    Writes the printer information to an XML file.

    .DESCRIPTION
    The Add-PrintersToXML function writes the details of the printer information to an XML file. It takes an XML writer
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


function Get-AclPathChecks {
    <#
    .SYNOPSIS
    Collects information about ACL checks for specified paths.

    .DESCRIPTION
    The Get-AclPathChecks function gathers information about ACL checks for specified paths on the system. It uses
    the Get-Acl cmdlet to query the ACL settings for the specified paths.

    .PARAMETER acl_path_checks
    An array list containing the paths for which ACL checks should be performed.

    .OUTPUTS
    [PSCustomObject]
    A custom object containing the ACL checks for specified paths.

    .EXAMPLE
    $aclPathChecks = Get-AclPathChecks
    #>
    param (
        [System.Collections.ArrayList]$acl_path_checks
    )
    $results = New-Object System.Collections.ArrayList
    foreach ($c in $acl_path_checks) {
        $path = [string] $c
        if (Test-Path $path) {
            $acl = Get-Acl -Path $path -ErrorAction SilentlyContinue
            $acl_list = New-Object System.Collections.ArrayList
            foreach ($a in $acl.Access) {
                [void]$acl_list.Add([PSCustomObject]@{
                    AccountName = [string] $a.IdentityReference
                    AccessControlType = [string] $a.AccessControlType
                    AccessRight = [string] $a.FileSystemRights
                })
            }
            $result = [PSCustomObject]@{
                Path = $path
                ACLs = $acl_list
            }
            [void]$results.Add($result)
        }
    }
    return ,$results
}

function Add-AclPathChecksToXML {
    <#
    .SYNOPSIS
    Writes the ACL checks for specified paths to an XML file.

    .DESCRIPTION
    The Add-AclPathChecksToXML function writes the details of the ACL checks for specified paths to an XML file. It takes
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
            $xmlWriter.WriteAttributeString("path", [string] $c.Path)
            $xmlWriter.WriteAttributeString("AccountName", [string] $a.AccountName)
            $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType)
            $xmlWriter.WriteAttributeString("AccessRight", [string] $a.AccessRight)
            $xmlWriter.WriteEndElement() # ACL
        }
        $xmlWriter.WriteEndElement() # ACLs
        $xmlWriter.WriteEndElement() # PathACL
    }
    $xmlWriter.WriteEndElement() # PathACLChecks
}

function Add-ConfigChecksToXML {
    <#
    .SYNOPSIS
    Writes the configuration checks to an XML file.

    .DESCRIPTION
    The Add-ConfigChecksToXML function writes the details of the configuration checks to an XML file. It takes an XML writer
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
            try{
                $xmlWriter.WriteStartElement("ConfigCheck")
                # the REVEAL importer reads Component, Name and Method as attributes
                $xmlWriter.WriteAttributeString("Component", [string] $c.Component)
                $xmlWriter.WriteAttributeString("Name", [string] $c.Name)
                $xmlWriter.WriteAttributeString("Method", [string] $c.Method)
                $xmlWriter.WriteElementString("Component", [string] $c.Component)
                $xmlWriter.WriteElementString("Name", [string] $c.Name)
                $xmlWriter.WriteElementString("Method", [string] $c.Method)
                $xmlWriter.WriteElementString("Key", [string] $c.Key)
                $xmlWriter.WriteElementString("Value", [string] $c.Value)
                $xmlWriter.WriteElementString("Result", [string] $c.Result)
                $xmlWriter.WriteElementString("Message", [string] $c.Message)
                $xmlWriter.WriteEndElement() # ConfigCheck
            } catch{}
        }
        $xmlWriter.WriteEndElement() # ConfigChecks
    }catch {
        Write-Host "[-] Config Checks could not be written to XML"
    }

}

function Get-ServicesInfo {

    $service_list = New-Object System.Collections.ArrayList

    $services = Get-WmiData -Class Win32_Service
    foreach ($s in $services ) {
        $service = [PSCustomObject]@{
            Caption = $s.Caption
            Description = $s.Description
            Name = $s.Name
            StartMode = $s.StartMode
            PathName = $s.PathName
            Started = $s.Started
            StartName = $s.StartName
            SystemName = $s.SystemName
            DisplayName = $s.DisplayName
            AcceptPause = $s.AcceptPause
            AcceptStop = $s.AcceptStop
            ProcessId = $s.ProcessId
            DelayedAutoStart = $s.DelayedAutoStart
        }
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
            $service | Add-Member -MemberType NoteProperty -Name Executable -Value $bin


            $space2 = $bin.IndexOf('"')
            if ($space2 -ne -1){
                $bin =$bin.Replace('"','')
            }

            $acl = get-acl -Path $bin -ErrorAction SilentlyContinue
            $bin_perms = New-Object System.Collections.ArrayList
            foreach ($a in $acl.Access) {
                try{
                    $perm = [PSCustomObject]@{
                        Name = [string] $s.Name
                        AccountName = [string] $a.IdentityReference
                        AccessControlType = [string] $a.AccessControlType
                        AccessRight = [string] $a.FileSystemRights
                    }
                    [void] $bin_perms.Add($perm)
                }catch{}
            }
            $service | Add-Member -MemberType NoteProperty -Name BinaryPermissions -Value $bin_perms


        } catch {}
        [void] $service_list.Add($service)
    }
    return ,$service_list
}

function Add-ServicesInfoToXML {
    <#
    .SYNOPSIS
    Writes the service information to an XML file.

    .DESCRIPTION
    The Add-ServicesInfoToXML function writes the details of the service information to an XML file. It takes an XML writer
    object and an array list of services as input.

    .PARAMETER xmlWriter
    An XML writer object used to write the service information to an XML file.

    .PARAMETER services
    An array list containing the service information.
    #>
    param (
        [System.Xml.XmlWriter]$xmlWriter,
        [System.Collections.ArrayList]$services
    )

    $xmlWriter.WriteStartElement("Services")
    foreach ($s in $services) {
        try{
            $xmlWriter.WriteStartElement("Service")
            $xmlWriter.WriteElementString("Caption", [string] $s.Caption)
            $xmlWriter.WriteElementString("Description",[string]$s.Description)
            $xmlWriter.WriteElementString("Name",[string]$s.Name)
            $xmlWriter.WriteElementString("StartMode",[string]$s.StartMode)
            $xmlWriter.WriteElementString("PathName", [string]$s.PathName)
            $xmlWriter.WriteElementString("Started",[string]$s.Started)
            $xmlWriter.WriteElementString("StartName",[string]$s.StartName)
            $xmlWriter.WriteElementString("SystemName",[string]$s.SystemName)
            $xmlWriter.WriteElementString("DisplayName",[string]$s.DisplayName)
            #$xmlWriter.WriteElementString("Running",[string]$s.Running)
            $xmlWriter.WriteElementString("AcceptStop",[string]$s.AcceptStop)
            $xmlWriter.WriteElementString("AcceptPause",[string]$s.AcceptPause)
            $xmlWriter.WriteElementString("ProcessId",[string]$s.ProcessId)
            $xmlWriter.WriteElementString("DelayedAutoStart",[string]$s.DelayedAutoStart)

            if ($s.PSObject.Properties.Name -contains "Executable") {
                $xmlWriter.WriteElementString("Executable",[string]$s.Executable)
            }
            if ($s.PSObject.Properties.Name -contains "BinaryPermissions") {
                $xmlWriter.WriteStartElement("BinaryPermissions")
                foreach ($a in $s.BinaryPermissions) {
                    $xmlWriter.WriteStartElement("Permission")
                    $xmlWriter.WriteAttributeString("Name", [string] $a.Name)
                    $xmlWriter.WriteAttributeString("AccountName", [string] $a.AccountName)
                    $xmlWriter.WriteAttributeString("AccessControlType", [string] $a.AccessControlType)
                    $xmlWriter.WriteAttributeString("AccessRight", [string] $a.AccessRight)
                    $xmlWriter.WriteEndElement() # Permission
                }
                $xmlWriter.WriteEndElement() # BinaryPermissions
            }
            $xmlWriter.WriteEndElement() # service
        }catch{}
    }
    $xmlWriter.WriteEndElement() # services
}

###############################################################################################################
# Collecting general computer information
###############################################################################################################
Write-Output "[*] Collecting general computer infos."

$hostInfo = Get-HostInfo

# Adding Hostname and infos from parameters to hostInfo object
$hostInfo.Hostname = $hostname
$hostInfo.SystemGroup = $Systemgroup
$hostInfo.Location = $Location
$hostInfo.Label = $Label
# date and time of the collection (same value as in the file name, format yyyyMMdd_HHmmss)
$hostInfo | Add-Member -MemberType NoteProperty -Name CollectionDate -Value $date -Force

###############################################################################################################
# Collecting BIOS information
###############################################################################################################
Write-Output "[*] Collecting BIOS information"
$biosInfo = Get-BIOSInfo

###############################################################################################################
# Collecting information about installed hotfixes / patches
###############################################################################################################
Write-Output "[*] Collecting installed hotfixes"
$hotfixes = Get-HotfixesInfo -host_info $hostInfo

###############################################################################################################
# Collecting information about installed products / applications
###############################################################################################################
Write-Output "[*] Collecting installed products"
$installedProducts = Get-InstalledProductsInfo -UseWin32Product:$UseWin32Product

###############################################################################################################
# Collecting information about network adapters
###############################################################################################################
Write-Output "[*] Collecting available network adapters"
$netadapters = Get-NetAdapterInfo

###############################################################################################################
# Collecting information about IP addresses
###############################################################################################################
Write-Output "[*] Collecting IP addresses"
$netips = Get-NetIPAddressInfo

###############################################################################################################
# Collecting information about available routes (routing table)
###############################################################################################################
Write-Output "[*] Collecting routing table"
$routes = Get-NetRouteInfo

###############################################################################################################
# Collecting information about local user accounts
###############################################################################################################
Write-Output "[*] Collecting local user accounts"
$users = Get-LocalUserAccountsInfo

###############################################################################################################
# Collecting information about local groups
###############################################################################################################
Write-Output "[*] Collecting local groups"
$groups = Get-LocalGroupsInfo

###############################################################################################################
# Perform: File Existence Checks
# This will check if specified files exist on the system and if they are matching a predefined hash.
# The matching of HASH is only performed in recent PowerShell versions by using Get-FileHash
###############################################################################################################
Write-Output "[*] Checking for existence of specified files"
$file_checks_results = Get-FileExistCheck -FileChecks $file_checks

###############################################################################################################
# Collecting information about firewall status
###############################################################################################################
Write-Output "[*] Collecting firewall status"
$firewallInfo = Get-FirewallInfo -config_check_results $config_check_results

###############################################################################################################
# Perform: Additional checks for entries in Windows Registry
#######################################################################
Write-Output "[*] Checking additional entries in Windows Registry"
$registry_check_results = Get-RegistryChecks -RegistryChecks $registry_checks

###############################################################################################################
# Collecting Share information
#######################################################################
Write-Output "[*] Collecting information about shares"
$shares = Get-SharesInfo

###############################################################################################################
# Collecting WSUS Settings in Registry
###############################################################################################################
Write-Output "[*] Checking WSUS configuration"
$wsusSettings = Get-WSUSSettings

###############################################################################################################
# Collecting autologon settings
###############################################################################################################
Write-Output "[*] Checking autologon settings"
$winlogon = Get-WinLogonInfo -config_checks $config_check_results


###############################################################################################################
# Collecting SSL / TLS settings
##############################################################################################################
Write-Output "[*] Checking SSL/TLS settings"
Test-TlsSettings -config_checks $config_check_results


###############################################################################################################
# Collecting PS Versions
##############################################################################################################
Write-Output "[*] Checking PS Versions"
$psVersions = Get-PSVersionsInfo -config_checks $config_check_results -hostInfo $hostInfo

###############################################################################################################
# Collecting WSH Settings
##############################################################################################################
Write-Output "[*] Checking WSH settings"
$wshSettings = Get-WSHSettings -config_checks $config_check_results

###############################################################################################################
# Check if LLMNR is enabled
###############################################################################################################
Write-Output "[*] Checking if LLMNR is enabled"
Test-LLMNR -config_checks $config_check_results

###############################################################################################################
# Check if SMB Signing is required
# https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview
###############################################################################################################
Write-Output "[*] Checking if SMB Signing is enabled"
Test-SMBSigning -config_checks $config_check_results


###############################################################################################################
# Collecting information about NTP configuration
###############################################################################################################
Write-Output "[*] Checking NTP configuration"
$ntpSettings = Get-NTPSettings

###############################################################################################################
# Collecting information about PowerShell (PS Logging enabled ?)
###############################################################################################################

# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1
Write-Output "[*] Checking PS Logging is enabled"
$psLogging = Get-PSLoggingInfo

###############################################################################################################
# Collecting information about SMB (Check if SMBv1 is enabled)
###############################################################################################################
Write-Output "[*] Checking if SMBv1 is enabled"
$smbConfig = Get-SMBConfig


###############################################################################################################
# Collecting information about Defender (Status / Settings)
###############################################################################################################
Write-Output "[*] Checking Defender settings"
$defenderInfo = Get-DefenderInfo


###############################################################################################################
# Collecting information about services
###############################################################################################################

Write-Output "[*] Collecting service information"
$services = Get-ServicesInfo

#
# TODO: Scheduled Task Checks
# TODO: fix Share permissions  and installed products to XML
###############################################################################################################
# Collecting information about Printer
###############################################################################################################
Write-Output "[*] Checking if printers are installed"
$printers = New-Object System.Collections.ArrayList
if (Get-Command Get-Printer -ea SilentlyContinue) {
    try {
        foreach ($p in Get-Printer -ea SilentlyContinue){
            $printer = [PSCustomObject]@{
                Name = [string] $p.Name
                ShareName = [string] $p.ShareName
                #Shareervice and ACL permissions. It's now -Depth 10.Name = [string] $p.ShareName
                Type = [string] $p.Type
                DriverName = [string] $p.DriverName
                PortName = [string] $p.PortName
                Shared = [string] $p.Shared
                Published = [string] $p.Published   
            }
            [void] $printers.Add($printer)
       }
    }catch{}
}

###############################################################################################################
# Perform: Path ACL Checks
###############################################################################################################
Write-Output "[*] Checking ACLs for specified pathes"
$aclPathChecks = Get-AclPathChecks -acl_path_checks $acl_path_checks





###############################################################################################################
# Writing collected information to XML file
###############################################################################################################
$basename = $path.Path + "\" + $date + "_SystemInfoCollector_" + $version + "_" + $hostname
$xmlfile  = $basename + ".xml"
$jsonfile = $basename + ".json"

if ($OutputFormat -in @('XML', 'Both')) {
    $xmlWriter = $null
    try {
        $settings =  New-Object System.Xml.XmlWriterSettings
        $settings.Indent = $true
        $settings.IndentChars = $(" "*4)
        $xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
        Write-Output "[*] Exporting data as XML"
        $xmlWriter.WriteStartDocument()
            $xmlWriter.WriteStartElement("SystemInfoCollector")
                $xmlWriter.WriteAttributeString("version", "$version")
                $xmlWriter.WriteStartElement("Host")
                    try {
                        Add-HostInfoToXML -xmlWriter $xmlWriter -hostInfo $hostInfo
                    } catch { Write-Output "[-] HostInfo could not be written to XML" }
                    try {
                        Add-BIOSInfoToXML -xmlWriter $xmlWriter -biosInfo $biosInfo
                    } catch { Write-Output "[-] BIOSInfo could not be written to XML" }
                    try {
                        Add-HotfixesToXML -xmlWriter $xmlWriter -hotfixes $hotfixes -hostInfo $hostInfo
                    } catch { Write-Output "[-] Hotfixes could not be written to XML" }
                    try {
                        Add-InstalledProductsToXML -xmlWriter $xmlWriter -products $installedProducts
                    } catch { Write-Output "[-] InstalledProducts could not be written to XML" }
                    try {
                        Add-NetAdapterToXML -xmlWriter $xmlWriter -netadapters $netadapters
                    } catch { Write-Output "[-] NetAdapter could not be written to XML" }
                    try {
                        Add-NetRouteToXML -xmlWriter $xmlWriter -routes $routes
                    } catch { Write-Output "[-] NetRoute could not be written to XML" }
                    try {
                        Add-NetIPAddressToXML -xmlWriter $xmlWriter -netips $netips
                    } catch { Write-Output "[-] NetIPAddress could not be written to XML" }
                    try {
                        Add-LocalUserAccountsToXML -xmlWriter $xmlWriter -users $users
                    } catch { Write-Output "[-] LocalUserAccounts could not be written to XML" }
                    try {
                        Add-LocalGroupsToXML -xmlWriter $xmlWriter -groups $groups
                    } catch { Write-Output "[-] LocalGroups could not be written to XML" }
                    try {
                        Add-FirewallInfoToXML -xmlWriter $xmlWriter -firewallInfo $firewallInfo
                    } catch { Write-Output "[-] FirewallInfo could not be written to XML" }
                    try {
                        Add-RegistryChecksToXML -xmlWriter $xmlWriter -registry_check_results $registry_check_results
                    } catch { Write-Output "[-] RegistryChecks could not be written to XML" }
                    try {
                        Add-ShareInfoToXML -xmlWriter $xmlWriter -shares $shares
                    } catch { Write-Output "[-] SharesInfo could not be written to XML" }
                    try {
                        Add-WSUSSettingsToXML -xmlWriter $xmlWriter -wsusSettings $wsusSettings
                    } catch { Write-Output "[-] WSUSSettings could not be written to XML" }
                    try {
                        Add-WinLogonToXML -xmlWriter $xmlWriter -winlogon $winlogon
                    } catch { Write-Output "[-] Winlogon could not be written to XML" }
                    try {
                        Add-PSVersionsToXML -xmlWriter $xmlWriter -psVersions $psVersions
                    } catch { Write-Output "[-] PSVersions could not be written to XML" }
                    try {
                        Add-WSHSettingsToXML -xmlWriter $xmlWriter -wshSettings $wshSettings
                    } catch { Write-Output "[-] WSHSettings could not be written to XML" }
                    try {
                        Add-NTPSettings-ToXML -xmlWriter $xmlWriter -ntpSettings $ntpSettings
                    } catch { Write-Output "[-] NTPSettings could not be written to XML" }
                    try {
                        Add-PSLoggingToXML -xmlWriter $xmlWriter -psLogging $psLogging
                    } catch { Write-Output "[-] PSLogging could not be written to XML" }
                    try {
                        Add-SMBConfigToXML -xmlWriter $xmlWriter -smbConfig $smbConfig
                    } catch { Write-Output "[-] SMBConfig could not be written to XML" }
                    try {
                        Add-DefenderInfoToXML -xmlWriter $xmlWriter -defenderInfo $defenderInfo
                    } catch { Write-Output "[-] DefenderInfo could not be written to XML" }
                    try {
                        Add-PrintersToXML -xmlWriter $xmlWriter -printers $printers
                    } catch { Write-Output "[-] Printers could not be written to XML" }
                    try {
                        Add-ServicesInfoToXML -xmlWriter $xmlWriter -services $services
                    } catch { Write-Output "[-] Services could not be written to XML" }
                    try {
                        Add-FileExistChecksToXML -xmlWriter $xmlWriter -file_checks_results $file_checks_results
                    } catch { Write-Output "[-] FileExistChecks could not be written to XML" }
                    try {
                        Add-AclPathChecksToXML -xmlWriter $xmlWriter -aclPathChecks $aclPathChecks
                    } catch { Write-Output "[-] AclPathChecks could not be written to XML" }
                    try {
                        Add-ConfigChecksToXML -xmlWriter $xmlWriter -configChecks $config_check_results
                    } catch { Write-Output "[-] ConfigChecks could not be written to XML" }
                $xmlWriter.WriteEndElement() # Host
            $xmlWriter.WriteEndElement() # SystemInfoCollector
        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        Write-Output "[+] XML file written to: $xmlfile"
    } catch {
        Write-Output "[-] XML file could not be written: $($_.Exception.Message)"
    } finally {
        if ($xmlWriter) { $xmlWriter.Close() }
    }
}

###############################################################################################################
# Writing collected information to JSON file
# The JSON file contains the same sections as the XML file. All collected objects are plain PSCustomObjects (no
# CIM/WMI objects), so the JSON file contains the same values as the XML file.
###############################################################################################################
if ($OutputFormat -in @('JSON', 'Both')) {
    try {
        Write-Output "[*] Exporting data as JSON"
        $json_obj = [PSCustomObject]@{
            Version = $version
            HostInfo = $hostInfo
            BiosInfo = $biosInfo
            Hotfixes = $hotfixes
            InstalledProducts = $installedProducts
            NetAdapter = $netadapters
            NetIPs = $netips
            Routes = $routes
            Users = $users
            Groups = $groups
            FileChecksResults = $file_checks_results
            FirewallInfo = $firewallInfo
            RegistryCheckResults = $registry_check_results
            Shares = $shares
            WsusSettings = $wsusSettings
            Winlogon = $winlogon
            PSVersions = $psVersions
            WSHSettings = $wshSettings
            NTPSettings = $ntpSettings
            PSLogging = $psLogging
            SMBConfig = $smbConfig
            DefenderInfo = $defenderInfo
            Printers = $printers
            Services = $services
            AclPathChecks = $aclPathChecks
            ConfigCheckResults = $config_check_results
        }
        # depth 10: the deepest nesting (e.g. Shares -> Share -> NTFSPermissions -> Permission) needs 5 levels.
        # The default depth of 2 (or the previously used 4) truncates nested objects to strings.
        $json = ConvertTo-Json -InputObject $json_obj -Depth 10
        # write UTF-8 without BOM (Out-File in PowerShell 5 writes UTF-16 by default)
        [System.IO.File]::WriteAllText($jsonfile, $json, (New-Object System.Text.UTF8Encoding($false)))
        Write-Output "[+] JSON file written to: $jsonfile"
    } catch {
        Write-Output "[-] JSON file could not be written: $($_.Exception.Message)"
    }
}
