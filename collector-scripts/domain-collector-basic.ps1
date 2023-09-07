<# 
    .SYNOPSIS
    This PowerShell script is to fetch domain information.

    .DESCRIPTION
    This PowerShell script is to fetch domain information. The collector script is published as part of "systemdb".
    https://github.com/c-bless/systemdb

    Author:     Christoph Bless (github@cbless.de)
    Version:    0.3.3
    License:    GPLv3

    In general the following data is collected: General information about the domain and the forest, domain trusts, list of
    domain controllers, password policies (default policy and fine grained policies). Furthermore, lists of computer and
    user accounts and domain groups are collected.

    The amount of data collected by the script differs depending on the version of the domain-collector script.

    domain-collector_full.ps1 : This version enumerates memberships for all domain groups. It also collects a larger
                                amount of attributes about computer accounts. It should be used for smaller domains.

    domain-collector.ps1 : This version enumerates memberships for the domain groups "Domain Admins",
                                 "Enterprise Admins", "Schema Admins", "ProtectedUsers". It also collects a
                                 larger amount of attributes about computer accounts.

    domain-collector_brief.ps1 : This version enumerates memberships for the domain groups "Domain Admins",
                                 "Enterprise Admins", "Schema Admins", "ProtectedUsers". It also collects a smaller amount
                                 of attributes about computer accounts. It could be used for larger domains.


    .INPUTS
    None
    
    .OUTPUTS
    This script will create a XML-file with the collected domain information. 
    
    .EXAMPLE
    .\domain-collector.ps1  

#>


# version number of this script used as attribute in XML root tag 
$version="0.1"
$script_type ="basic"

$date = Get-Date -Format "yyyyMMdd_HHmmss"
$path = Get-Location



$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$forestObj = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()



$name = [string] $domainObj.Name
$xmlfile = $path.Path + "\" + $date + "_DomainCollector_"+$script_type+"_"+$version+"_" + $name + ".xml"


$settings =  New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.IndentChars = $(" "*4)

$xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
$xmlWriter.WriteStartDocument()

$xmlWriter.WriteStartElement("DomainCollector")
    $xmlWriter.WriteAttributeString("version", "$version")
    $xmlWriter.WriteAttributeString("type", "$script_type")
    $xmlWriter.WriteStartElement("ADDomain")
        $xmlWriter.WriteElementString("Name", [string] $domainObj.Name);
        # https://eightwone.com/references/ad-functional-levels
        $xmlWriter.WriteElementString("DomainMode", [string] $domainObj.DomainMode);
        $xmlWriter.WriteElementString("DomainModeLevel", [string] $domainObj.DomainModeLevel);
        $xmlWriter.WriteElementString("Parent", [string] $domainObj.Parent);
        $xmlWriter.WriteElementString("DomainSID", [string] $domainObj.DomainSID);
        $xmlWriter.WriteElementString("RIDMaster", [string] $domainObj.RidRoleOwner);
        $xmlWriter.WriteElementString("PDCEmulator", [string] $domainObj.PdcRoleOwner);
        $xmlWriter.WriteElementString("ParentDomain", [string] $domainObj.ParentDomain);
        $xmlWriter.WriteElementString("Forest", [string] $domainObj.Forest);
        $xmlWriter.WriteElementString("InfrastructureMaster", [string] $domainObj.InfrastructureRoleOwner);
    $xmlWriter.WriteEndElement() # ADDomain

    $xmlWriter.WriteStartElement("ADForest")

        $xmlWriter.WriteElementString("DomainNamingMaster", [string] $forestObj.DomainNamingMaster);
            $xmlWriter.WriteElementString("Name", [string] $forestObj.Name);
            $xmlWriter.WriteElementString("RootDomain", [string] $forestObj.RootDomain);
            $xmlWriter.WriteElementString("SchemaMaster", [string] $forestObj.SchemaRoleOwner);
            $xmlWriter.WriteStartElement("Sites")
                foreach ($s in $forestObj.Sites) {
                    $xmlWriter.WriteElementString("Site", [string] $s.Name);
                }
            $xmlWriter.WriteEndElement()
            $xmlWriter.WriteStartElement("GlobalCatalogs")
                foreach ($gc in $forestObj.GlobalCatalogs) {
                    $xmlWriter.WriteElementString("GlobalCatalog", [string] $gc.Name);
                }
        $xmlWriter.WriteEndElement() # GC

    $xmlWriter.WriteEndElement() # ADForest



    $xmlWriter.WriteStartElement("ADTrusts")
        foreach ($t in $domainObj.GetAllTrustRelationships()){
            $xmlWriter.WriteStartElement("ADTrust")
                $xmlWriter.WriteElementString("Source", [string] $t.SourceName);
                $xmlWriter.WriteElementString("Target", [string] $t.TargetName);
                $xmlWriter.WriteElementString("Direction", [string] $t.TrustDirection);
                $xmlWriter.WriteElementString("TrustType", [string] $t.TrustType);
            $xmlWriter.WriteEndElement() # ADTrust            
        }
    $xmlWriter.WriteEndElement() # ADTrusts


    $xmlWriter.WriteStartElement("ADDomainControllerList")
    try{
        $dc_list = $domainObj.DomainControllers
        foreach ($dc in $dc_list) {
            try {
                $xmlWriter.WriteStartElement("ADDomainController")
                    $xmlWriter.WriteElementString("Name", [string] $dc.Name);
                    $xmlWriter.WriteElementString("Hostname", [string] $dc.Name);
                    $xmlWriter.WriteElementString("OperatingSystem", [string] $dc.OSVersion);
                    $xmlWriter.WriteElementString("IPv4Address", [string] $dc.IPAddress);
                    $xmlWriter.WriteElementString("Domain", [string] $dc.Domain);
                    $xmlWriter.WriteElementString("Forest", [string] $dc.Forest);
                    $xmlWriter.WriteElementString("IsGlobalCatalog", [string] $dc.IsGlobalCatalog());
                    $xmlWriter.WriteStartElement("Roles")
                        foreach ($s in $dc.Roles) {
                            $xmlWriter.WriteElementString("Role", [string] $s.ToString());
                        }
                    $xmlWriter.WriteEndElement() # ServerRoles
                $xmlWriter.WriteEndElement() #ADDomainController
            } catch {
                # Ignore this ADDomainController object and try to parse the next. No Tag will be added for this one. 
            }
        }
    } catch {
        # Failed executions will be ignored and no ADDomainController tags will be added under ADDomainControllerList
    }
    $xmlWriter.WriteEndElement() # DomainControllerList


    $xmlWriter.WriteStartElement("ADUserList")
    try{
        # Set the properties to retrieve. $basic_properties will contain all properties that can be added as 
        # new XML Element
        $basic_properties = @(
            'DistinguishedName', 'SID', 'SAMAccountName', 'displayName', 'Description', 'GivenName', 'Surname', 'Name',
            'PasswordLastSet', 'PasswordNeverExpires','PasswordNotRequired'
        )
        $searcher = [adsisearcher][adsi]''
        $searcher.Filter = '(&(objectCategory=Person)(objectClass=User)(userAccountControl:1.2.840.113556.1.4.803:=2)'
        
        foreach ($p in $basic_properties){
            $key = $p.ToLower() 
            $searcher.PropertiesToLoad($key)
        }
        
        $users = $searcher.FindAll().GetEnumerator() 

        foreach ($u in $users) {
            try{
                $xmlWriter.WriteStartElement("ADUser");
                $xmlWriter.WriteElementString("DistinguishedName", [string] $u.Properties.distinguishedname);
                $xmlWriter.WriteElementString("SID",[string] $u.Properties.objectsid);
                $xmlWriter.WriteElementString("SAMAccountName", [string] $u.Properties.samaccountname);
                $xmlWriter.WriteElementString("Description",[string]$u.Properties.description);
                $xmlWriter.WriteElementString("GivenName",[string]$u.Properties.givenname);
                $xmlWriter.WriteElementString("Surname",[string]$u.Properties.surname);
                $xmlWriter.WriteElementString("Name",[string]$u.Properties.name);
                $xmlWriter.WriteElementString("PasswordLastSet",[string]$u.Properties.pwdlastset);
                $xmlWriter.WriteElementString("PasswordNeverExpires",[string]$u.Properties.accountexpires);
                $xmlWriter.WriteElementString("UserAccountControl",[string]$u.Properties.useraccountcontrol);
                $xmlWriter.WriteEndElement() #ADUser
            } catch {
                # Ignore this ADUser object and try to parse the next. No Tag will be added for this one. 
            }
        }
    } catch {
        # Failed executions will be ignored and no ADUser tags will be added under ADUserList
    }
    $xmlWriter.WriteEndElement() # ADUserList   

$xmlWriter.WriteEndElement() # DomainCollector

$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()
