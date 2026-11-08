
# version number of this script used as attribute in XML root tag 
$version="DEV"
$script_type ="basic"

$date = Get-Date -Format "yyyyMMdd_HHmmss"
$path = Get-Location



$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$forestObj = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()


$domainInfo = [PSCustomObject]@{
    "Name" = [string] $domainObj.Name
    "DomainMode", [string] $domainObj.DomainMode
    "DomainModeLevel", [string] $domainObj.DomainModeLevel
    "Parent", [string] $domainObj.Parent
    "DomainSID", [string] $domainObj.DomainSID
    "RIDMaster", [string] $domainObj.RidRoleOwner
    "PDCEmulator", [string] $domainObj.PdcRoleOwner
    "ParentDomain", [string] $domainObj.ParentDomain    
    "Forest", [string] $domainObj.Forest
    "InfrastructureMaster", [string] $domainObj.InfrastructureRoleOwner
}



$domainTrusts = New-Object System.Collections.ArrayList

foreach ($t in $domainObj.GetAllTrustRelationships()){
    $trust = [PSCustomObject]@{
        "Source", [string] $t.SourceName
        "Target", [string] $t.TargetName
        "Direction", [string] $t.TrustDirection
        "TrustType", [string] $t.TrustType
    }
    [void] $domainTrusts.Add($trust)
}


$result = [PSCustomObject]@{
    ADDomain = $domainInfo
    ADTrust = $domainTrusts
}

$jsonfile = $path.Path + "\" + $date + "_DomainCollector_"+$version+"_" + $domainObj.Name + ".json"

$result |ConvertTo-Json -depth 2 | Out-File -FilePath $jsonfile 