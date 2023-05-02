<# 
    .SYNOPSIS
    This PowerShell script is to fetch domain information.

    .DESCRIPTION
    This PowerShell script is to fetch domain information. The collector script is published as part of "systemdb".
    https://bitbucket.org/cbless/systemdb

    Author: Christoph Bless (bitbucket@cbless.de)

    .INPUTS
    None
    
    .OUTPUTS
    This script will create a XML-file with the collected domain information. 
    
    .EXAMPLE
    .\domain-collector.ps1  

#>
$date = Get-Date -Format "yyyyMMdd_HHmmss"
import-module ActiveDirectory


$domain = Get-ADDomain;

$path = Get-Location

$xmlfile = $path.Path + "\" + $date + "_" + [string] $domain.NetBIOSName + ".xml"


$settings =  New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.IndentChars = $(" "*4)

$xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
$xmlWriter.WriteStartDocument()


$xmlWriter.WriteStartElement("DomainCollector")
    $xmlWriter.WriteStartElement("ADDomain")
        $xmlWriter.WriteElementString("Name", [string] $domain.Name);
        $xmlWriter.WriteElementString("NetBIOSName", [string] $domain.NetBIOSName);
        $xmlWriter.WriteElementString("DomainMode", [string] $domain.DomainMode);
        $xmlWriter.WriteElementString("DNSRoot", [string] $domain.DNSRoot);
        $xmlWriter.WriteElementString("DomainSID", [string] $domain.DomainSID);
        $xmlWriter.WriteElementString("RIDMaster", [string] $domain.RIDMaster);
        $xmlWriter.WriteElementString("PDCEmulator", [string] $domain.PDCEmulator);
        $xmlWriter.WriteElementString("ParentDomain", [string] $domain.ParentDomain);
        $xmlWriter.WriteElementString("Forest", [string] $domain.Forest);
        $xmlWriter.WriteElementString("UsersContainer", [string] $domain.UsersContainer);
        $xmlWriter.WriteElementString("SystemsContainer", [string] $domain.SystemsContainer);
        $xmlWriter.WriteElementString("ComputersContainer", [string] $domain.ComputersContainer);
        $xmlWriter.WriteElementString("DistinguishedName", [string] $domain.DistinguishedName);
        $xmlWriter.WriteElementString("InfrastructureMaster", [string] $domain.InfrastructureMaster);
    $xmlWriter.WriteEndElement() # ADDomain

    
    $forest = Get-ADForest 
    $xmlWriter.WriteStartElement("ADForest")
        $xmlWriter.WriteElementString("DomainNamingMaster", [string] $forest.DomainNamingMaster);
        $xmlWriter.WriteElementString("Name", [string] $forest.Name);
        $xmlWriter.WriteElementString("RootDomain", [string] $forest.RootDomain);
        $xmlWriter.WriteElementString("SchemaMaster", [string] $forest.SchemaMaster);
        $xmlWriter.WriteStartElement("Sites")
            foreach ($s in $forest.Sites) {
                $xmlWriter.WriteElementString("Site", [string] $s.Name);
            }
        $xmlWriter.WriteEndElement()
        $xmlWriter.WriteStartElement("GlobalCatalogs")
            foreach ($gc in $forest.GlobalCatalogs) {
                $xmlWriter.WriteElementString("GlobalCatalog", [string] $gc);
            }
        $xmlWriter.WriteEndElement() # GC
    $xmlWriter.WriteEndElement() # ADForest

    $trust = Get-ADTrust -Filter *
    $xmlWriter.WriteStartElement("ADTrust")
        $xmlWriter.WriteElementString("Source", [string] $trust.Source);
        $xmlWriter.WriteElementString("Target", [string] $trust.Target);
        $xmlWriter.WriteElementString("Direction", [string] $trust.Direction);
        $xmlWriter.WriteElementString("TrustType", [string] $trust.TrustType);
        $xmlWriter.WriteElementString("UplevelOnly", [string] $trust.UplevelOnly);
        $xmlWriter.WriteElementString("UsesAESKeys", [string] $trust.UsesAESKeys);
        $xmlWriter.WriteElementString("UsesRC4Encryption", [string] $trust.UsesRC4Encryption);
        $xmlWriter.WriteElementString("TGTDelegation", [string] $trust.TGTDelegation);
        $xmlWriter.WriteElementString("SIDFilteringForestAware", [string] $trust.SIDFilteringForestAware);
        $xmlWriter.WriteElementString("SIDFilteringQuarantined", [string] $trust.SIDFilteringQuarantined);
        $xmlWriter.WriteElementString("SelectiveAuthentication", [string] $trust.SelectiveAuthentication);
        $xmlWriter.WriteElementString("DisallowTransivity", [string] $trust.DisallowTransivity);
        $xmlWriter.WriteElementString("DistinguishedName", [string] $trust.DistinguishedName);
        $xmlWriter.WriteElementString("ForestTransitive", [string] $trust.ForestTransitive);
        $xmlWriter.WriteElementString("IntraForest", [string] $trust.IntraForest);
        $xmlWriter.WriteElementString("IsTreeParent", [string] $trust.IsTreeParent);
        $xmlWriter.WriteElementString("IsTreeRoot", [string] $trust.IsTreeRoot);
    $xmlWriter.WriteEndElement() # ADTrust

    $dc_list = Get-ADDomainController
    $xmlWriter.WriteStartElement("ADDomainControllerList")
        foreach ($dc in $dc_list) {
            $xmlWriter.WriteStartElement("ADDomainController")
            $xmlWriter.WriteElementString("Name", [string] $dc.Name);
            $xmlWriter.WriteElementString("Hostname", [string] $dc.Hostname);
            $xmlWriter.WriteElementString("OperatingSystem", [string] $dc.OperatingSystem);
            $xmlWriter.WriteElementString("IPv4Address", [string] $dc.IPv4Address);
            $xmlWriter.WriteElementString("IPv6Address", [string] $dc.IPv6Address);
            $xmlWriter.WriteElementString("Enabled", [string] $dc.Enabled);
            $xmlWriter.WriteElementString("Domain", [string] $dc.Domain);
            $xmlWriter.WriteElementString("Forest", [string] $dc.Forest);
            $xmlWriter.WriteElementString("IsGlobalCatalog", [string] $dc.IsGlobalCatalog);
            $xmlWriter.WriteElementString("IsReadOnly", [string] $dc.IsReadOnly);
            $xmlWriter.WriteElementString("LdapPort", [string] $dc.LdapPort);
            $xmlWriter.WriteElementString("SslPort", [string] $dc.SslPort);
            $xmlWriter.WriteStartElement("ServerRoles")
            foreach ($s in $dc.ServerRoles) {
                $xmlWriter.WriteElementString("Role", [string] $s);
            }
            $xmlWriter.WriteEndElement() # ServerRoles
            $xmlWriter.WriteStartElement("OperationMasterRoles")
            foreach ($s in $dc.OperationMasterRoles) {
                $xmlWriter.WriteElementString("Role", [string] $s);
            }
            $xmlWriter.WriteEndElement() # servicePrincipalNames
            $xmlWriter.WriteEndElement()
        }
    $xmlWriter.WriteEndElement() # DomainControllerList


    $computer_list = Get-ADComputer -Filter * -Properties *
    $xmlWriter.WriteStartElement("ADComputerList")
        foreach ($c in $computer_list) {
            $xmlWriter.WriteStartElement("ADComputer")
            $xmlWriter.WriteElementString("DistinguishedName", [string] $c.DistinguishedName);
            $xmlWriter.WriteElementString("DNSHostName", [string] $c.DNSHostName );
            $xmlWriter.WriteElementString("Enabled", [string] $c.Enabled);
            $xmlWriter.WriteElementString("IPv4Address", [string] $c.IPv4Address);
            $xmlWriter.WriteElementString("IPv6Address", [string] $c.IPv6Address);
            $xmlWriter.WriteElementString("SID", [string] $c.SID);
            $xmlWriter.WriteElementString("SamAccountName", [string] $c.SamAccountName);
            $xmlWriter.WriteElementString("ServiceAccount", [string] $c.ServiceAccount);
            $xmlWriter.WriteElementString("servicePrincipalNamesStr", [string] $c.servicePrincipalNames);
            $xmlWriter.WriteStartElement("servicePrincipalNames")
            foreach ($s in $c.ServicePrincipalNames) {
                $xmlWriter.WriteElementString("SPN", [string] $s);
            }
            $xmlWriter.WriteEndElement() # servicePrincipalNames
            $xmlWriter.WriteElementString("TrustedForDelegation", [string] $c.TrustedForDelegation);
            $xmlWriter.WriteElementString("TrustedToAuthForDelegation", [string] $c.TrustedToAuthForDelegation);
            $xmlWriter.WriteElementString("PrimaryGroup", [string] $c.PrimaryGroup);
            $xmlWriter.WriteElementString("primaryGroupID", [string] $c.primaryGroupID);
            $xmlWriter.WriteElementString("pwdLastSet", [string] $c.pwdLastSet);
            $xmlWriter.WriteElementString("ProtectedFromAccidentalDeletion", [string] $c.ProtectedFromAccidentalDeletion);
            $xmlWriter.WriteElementString("OperatingSystem", [string] $c.OperatingSystem);
            $xmlWriter.WriteElementString("OperatingSystemVersion", [string] $c.OperatingSystemVersion);
            $xmlWriter.WriteElementString("Description", [string] $c.Description);
            $xmlWriter.WriteEndElement()
        }
    $xmlWriter.WriteEndElement() # ComputerList

    $user_list = Get-ADUser -Filter * -Properties * 
    $xmlWriter.WriteStartElement("ADUserList")
        foreach ($u in $user_list) {
            $xmlWriter.WriteStartElement("ADUser");
            $xmlWriter.WriteElementString("SAMAccountName", [string] $u.SAMAccountName);
            $xmlWriter.WriteElementString("DistinguishedName", [string] $u.DistinguishedName);
            $xmlWriter.WriteElementString("SID", [string] $u.SID);
            $xmlWriter.WriteElementString("GivenName", [string] $u.GivenName);
            $xmlWriter.WriteElementString("Surname", [string] $u.Surname);
            $xmlWriter.WriteElementString("Name", [string] $u.Name);
            $xmlWriter.WriteElementString("SIDHistory", [string] $u.SIDHistory);
            $xmlWriter.WriteElementString("Enabled", [string] $u.Enabled);
            $xmlWriter.WriteElementString("Description", [string] $u.Description);
            $xmlWriter.WriteElementString("DistinguishedName", [string] $u.DistinguishedName);
            $xmlWriter.WriteElementString("BadLogonCount", [string] $u.BadLogonCount);
            $xmlWriter.WriteElementString("BadPwdCount", [string] $u.BadPwdCount);
            $xmlWriter.WriteElementString("Created", [string] $u.Created);
            $xmlWriter.WriteElementString("LastBadPasswordAttempt", [string] $u.LastBadPasswordAttempt);
            $xmlWriter.WriteElementString("lastLogon", [string] $u.lastLogon);
            $xmlWriter.WriteElementString("LastLogonDate", [string] $u.LastLogonDate);
            $xmlWriter.WriteElementString("logonCount", [string] $u.logonCount);
            $xmlWriter.WriteElementString("LockedOut", [string] $u.LockedOut);
            $xmlWriter.WriteElementString("PasswordExpired", [string] $u.PasswordExpired);
            $xmlWriter.WriteElementString("PasswordLastSet", [string] $u.PasswordLastSet);
            $xmlWriter.WriteElementString("PasswordNeverExpires", [string] $u.PasswordNeverExpires);
            $xmlWriter.WriteElementString("PasswordNotRequired", [string] $u.PasswordNotRequired);
            $xmlWriter.WriteElementString("pwdLastSet", [string] $u.pwdLastSet);
            $xmlWriter.WriteElementString("Modified", [string] $u.Modified);
            $xmlWriter.WriteStartElement("MemberOf");
            foreach ($m in $u.MemberOf) {
                $xmlWriter.WriteElementString("Group", [string] $m);
            }
            $xmlWriter.WriteEndElement(); # MemberOf
            $xmlWriter.WriteElementString("MemberOfStr", [string] $u.MemberOf);
            $xmlWriter.WriteEndElement(); # User         
            
        }
    $xmlWriter.WriteEndElement() # UserList


    $group_list = Get-ADGroup -Filter * -Properties * 
    $xmlWriter.WriteStartElement("ADGroupList")
        foreach ($g in $group_list) {
            $xmlWriter.WriteStartElement("ADGroup");
            $xmlWriter.WriteElementString("CN", [string] $g.CN);
            $xmlWriter.WriteElementString("Description", [string] $g.Description);
            $xmlWriter.WriteElementString("GroupCategory", [string] $g.GroupCategory);
            $xmlWriter.WriteElementString("GroupScope", [string] $g.GroupScope);
            $xmlWriter.WriteElementString("SamAccountName", [string] $g.SamAccountName);
            $xmlWriter.WriteElementString("SID", [string] $g.SID);
            $xmlWriter.WriteElementString("MemberOfStr", [string] $g.MemberOf);
            $xmlWriter.WriteStartElement("Members");
            $members = Get-ADGroupMember -Identity $g.SamAccountName
            foreach ($m in $members) {
                $xmlWriter.WriteStartElement("Member");
                $xmlWriter.WriteAttributeString("SamAccountName", [string] $m.SamAccountName)
                $xmlWriter.WriteAttributeString("SID", [string] $m.SID)
                $xmlWriter.WriteAttributeString("name", [string] $m.Name)
                $xmlWriter.WriteAttributeString("distinguishedName", [string] $m.distinguishedName)
                $xmlWriter.WriteEndElement(); # Member
            
            }
            $xmlWriter.WriteEndElement(); # Members
            $xmlWriter.WriteEndElement(); # User         
            
        }
    $xmlWriter.WriteEndElement() # UserList

$xmlWriter.WriteEndElement() # DomainCollector
$xmlWriter.WriteEndDocument()
$xmlWriter.Flush()
$xmlWriter.Close()
