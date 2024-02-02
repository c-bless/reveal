<# 
    .SYNOPSIS
    This PowerShell script is to fetch domain information.

    .DESCRIPTION
    This PowerShell script is to fetch domain information. The collector script is published as part of "REVEAL".
    https://github.com/c-bless/reveal

    Author:     Christoph Bless (github@cbless.de)
    Version:    0.4.3
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
$version="0.4.3"
$script_type ="full"

$date = Get-Date -Format "yyyyMMdd_HHmmss"
import-module ActiveDirectory -ErrorAction SilentlyContinue


try{
    # check if command from activedirectory module is available. If if it not installed (command above would fail),
    # it can be imported manually before executing the script.
    if (Get-Command Get-ADDomain) {
        Write-Host "[*] Collecting Domain information."
        $start_of_script = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $domain = Get-ADDomain;
        $path = Get-Location

        $name = [string] $domain.NetBIOSName
        $xmlfile = $path.Path + "\" + $date + "_DomainCollector_full_"+$version+"_" + $name + ".xml"


        $settings =  New-Object System.Xml.XmlWriterSettings
        $settings.Indent = $true
        $settings.IndentChars = $(" "*4)

        $xmlWriter = [System.Xml.XmlWriter]::Create($xmlfile, $settings)
        $xmlWriter.WriteStartDocument()


        #############################################################################################################
        #    Collecting Basic information about the current domain
        #    Note: successful execution of ADDomain and ADForest is required sine these are referenced when imported
        #    to REVEAL, therefore a global try catch is wrapped around all commands
        #############################################################################################################
        $xmlWriter.WriteStartElement("DomainCollector")
            $xmlWriter.WriteAttributeString("version", "$version")
            $xmlWriter.WriteAttributeString("type", "$script_type")
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

            #############################################################################################################
            #    Collecting Basic information about the current Forest
            #    Note: successful execution of ADDomain and ADForest is requrired sine these are referenced when imported 
            #    to systemdb, therefore a global try catch is wrapped around all commands
            #############################################################################################################
            Write-Host "[*] Collecting forest information." 
            $forest = Get-ADForest 
            $xmlWriter.WriteStartElement("ADForest")
                $xmlWriter.WriteElementString("DomainNamingMaster", [string] $forest.DomainNamingMaster);
                $xmlWriter.WriteElementString("Name", [string] $forest.Name);
                $xmlWriter.WriteElementString("RootDomain", [string] $forest.RootDomain);
                $xmlWriter.WriteElementString("SchemaMaster", [string] $forest.SchemaMaster);
                $xmlWriter.WriteStartElement("Sites")
                    foreach ($s in $forest.Sites) {
                        $xmlWriter.WriteElementString("Site", [string] $s);
                    }
                $xmlWriter.WriteEndElement()
                $xmlWriter.WriteStartElement("GlobalCatalogs")
                    foreach ($gc in $forest.GlobalCatalogs) {
                        $xmlWriter.WriteElementString("GlobalCatalog", [string] $gc);
                    }
                $xmlWriter.WriteEndElement() # GC
            $xmlWriter.WriteEndElement() # ADForest

            #############################################################################################################
            #    Collecting information about domain trusts
            #    Note: Failed executions will be ignored and no ADTrust tags will be added to ADTrusts
            #############################################################################################################
            if (Get-Command Get-ADTrust -ErrorAction SilentlyContinue) {
                Write-Host "[*] Collecting AD trust information." 
                $xmlWriter.WriteStartElement("ADTrusts")
                try {
                    if ($trust = Get-ADTrust -Filter * -ErrorAction SilentlyContinue){
                        foreach ($t in $trust){
                            try {
                                $xmlWriter.WriteStartElement("ADTrust")
                                    $xmlWriter.WriteElementString("Source", [string] $t.Source);
                                    $xmlWriter.WriteElementString("Target", [string] $t.Target);
                                    $xmlWriter.WriteElementString("Direction", [string] $t.Direction);
                                    $xmlWriter.WriteElementString("TrustType", [string] $t.TrustType);
                                    $xmlWriter.WriteElementString("UplevelOnly", [string] $t.UplevelOnly);
                                    $xmlWriter.WriteElementString("UsesAESKeys", [string] $t.UsesAESKeys);
                                    $xmlWriter.WriteElementString("UsesRC4Encryption", [string] $t.UsesRC4Encryption);
                                    $xmlWriter.WriteElementString("TGTDelegation", [string] $t.TGTDelegation);
                                    $xmlWriter.WriteElementString("SIDFilteringForestAware", [string] $t.SIDFilteringForestAware);
                                    $xmlWriter.WriteElementString("SIDFilteringQuarantined", [string] $t.SIDFilteringQuarantined);
                                    $xmlWriter.WriteElementString("SelectiveAuthentication", [string] $t.SelectiveAuthentication);
                                    $xmlWriter.WriteElementString("DisallowTransivity", [string] $t.DisallowTransivity);
                                    $xmlWriter.WriteElementString("DistinguishedName", [string] $t.DistinguishedName);
                                    $xmlWriter.WriteElementString("ForestTransitive", [string] $t.ForestTransitive);
                                    $xmlWriter.WriteElementString("IntraForest", [string] $t.IntraForest);
                                    $xmlWriter.WriteElementString("IsTreeParent", [string] $t.IsTreeParent);
                                    $xmlWriter.WriteElementString("IsTreeRotrustot", [string] $t.IsTreeRoot);
                                $xmlWriter.WriteEndElement() # ADTrust
                            } catch{
                                # Ignore this ADTrust object and try to parse the next. No Tag will be added for this one. 
                            }
                        }
                    }
                } catch {
                    # Failed executions will be ignored and no ADTrust tags will be added under ADTrusts
                }
                $xmlWriter.WriteEndElement() # ADTrusts
            } 
    
            #############################################################################################################
            #    Collecting information about domain controllers
            #    Note: Failed executions will be ignored and no ADDomainController tags will be added to 
            #    ADDomainControllerList
            #############################################################################################################
            if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
                Write-Host "[*] Collecting Domain Controller list."
                $start_of_dc = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                $xmlWriter.WriteStartElement("ADDomainControllerList")
                try{
                    $dc_list = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
                    foreach ($dc in $dc_list) {
                        try {
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
                            $xmlWriter.WriteEndElement() #ADDomainController
                        } catch {
                            # Ignore this ADDomainController object and try to parse the next. No Tag will be added for this one. 
                        }
                    }
                } catch {
                    # Failed executions will be ignored and no ADDomainController tags will be added under ADDomainControllerList
                }
                $xmlWriter.WriteEndElement() # DomainControllerList
                $end_of_dc = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }

            
            #############################################################################################################
            #    Collecting information about the default domain password policy
            #    Note: Failed executions will be ignored and no ADDefaultDomainPasswordPolicy will be added
            #############################################################################################################
            if (Get-Command Get-ADDefaultDomainPasswordPolicy -ea SilentlyContinue) {
                Write-Host "[*] Collecting Default Domain Password Policy." 
                try {
                    $pw_policy = Get-ADDefaultDomainPasswordPolicy -ea SilentlyContinue 
                    $xmlWriter.WriteStartElement("ADDefaultDomainPasswordPolicy");
                    $xmlWriter.WriteElementString("ComplexityEnabled", [string] $pw_policy.ComplexityEnabled);
                    $xmlWriter.WriteElementString("DistinguishedName", [string] $pw_policy.DistinguishedName);
                    $xmlWriter.WriteElementString("LockoutDuration", [string] $pw_policy.LockoutDuration);
                    $xmlWriter.WriteElementString("LockoutObservationWindow", [string] $pw_policy.LockoutObservationWindow);
                    $xmlWriter.WriteElementString("LockoutThreshold", [string] $pw_policy.LockoutThreshold);
                    $xmlWriter.WriteElementString("MaxPasswordAge", [string] $pw_policy.MaxPasswordAge);
                    $xmlWriter.WriteElementString("MinPasswordAge", [string] $pw_policy.MinPasswordAge);
                    $xmlWriter.WriteElementString("MinPasswordLength", [string] $pw_policy.MinPasswordLength);
                    $xmlWriter.WriteElementString("PasswordHistoryCount", [string] $pw_policy.PasswordHistoryCount);
                    $xmlWriter.WriteElementString("ReversibleEncryptionEnabled", [string] $pw_policy.ReversibleEncryptionEnabled);
                    $xmlWriter.WriteEndElement() # ADDefaultDomainPasswordPolicy
                }catch {
                    # Failed executions will be ignored and no ADDefaultDomainPasswordPolicy will be added
                }
            }
            
            
            #############################################################################################################
            #    Collecting information about all fine grained password policies in the current domain
            #    Note: Failed executions will be ignored and no Policy will be added to ADFineGrainedPasswordPolicies
            #############################################################################################################
            if (Get-Command Get-ADFineGrainedPasswordPolicy -ea SilentlyContinue){
                Write-Host "[*] Collecting Fine Grained Password Policy." 
                $xmlWriter.WriteStartElement("ADFineGrainedPasswordPolicies");
                try {
                    $pw_policy = Get-ADFineGrainedPasswordPolicy -Filter * -ea SilentlyContinue                     
                    foreach ($p in $pw_policy) {
                        try{
                            $xmlWriter.WriteStartElement("Policy");
                            $xmlWriter.WriteElementString("Name", [string] $pw_policy.Name);
                            $xmlWriter.WriteElementString("ComplexityEnabled", [string] $pw_policy.ComplexityEnabled);
                            $xmlWriter.WriteElementString("DistinguishedName", [string] $pw_policy.DistinguishedName);
                            $xmlWriter.WriteElementString("LockoutDuration", [string] $pw_policy.LockoutDuration);
                            $xmlWriter.WriteElementString("LockoutObservationWindow", [string] $pw_policy.LockoutObservationWindow);
                            $xmlWriter.WriteElementString("LockoutThreshold", [string] $pw_policy.LockoutThreshold);
                            $xmlWriter.WriteElementString("MaxPasswordAge", [string] $pw_policy.MaxPasswordAge);
                            $xmlWriter.WriteElementString("MinPasswordAge", [string] $pw_policy.MinPasswordAge);
                            $xmlWriter.WriteElementString("MinPasswordLength", [string] $pw_policy.MinPasswordLength);
                            $xmlWriter.WriteElementString("PasswordHistoryCount", [string] $pw_policy.PasswordHistoryCount);
                            $xmlWriter.WriteElementString("ReversibleEncryptionEnabled", [string] $pw_policy.ReversibleEncryptionEnabled);
                            $xmlWriter.WriteEndElement() # Policy
                        }catch {
                            # Ignore this Policy object and try to parse the next. No Tag will be added for this one. 
                        }
                    }
                }catch {
                    # Failed executions will be ignored and no policies tags will be added under ADFineGrainedPasswordPolicies
                }
                $xmlWriter.WriteEndElement() # ADFineGrainedPasswordPolicies
                
            }
    
            #############################################################################################################
            #    Collecting information about domain computers
            #    Note: Failed executions will be ignored and no ADComputer tags will be added to ADComputerList
            #############################################################################################################
            if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
                Write-Host "[*] Collecting information about AD computer." 
                $start_of_comp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                $xmlWriter.WriteStartElement("ADComputerList")
                try {
                    # Set the properties to retrieve. $basic_properties will contain all properties that can be added as 
                    # new XML Element
                    $basic_properties = @(
                        'DistinguishedName', 'DNSHostName', 'Enabled', 'SID', 'SamAccountName', 'IPv4Address', 'IPv6Address',
                        'ServiceAccount', 'TrustedForDelegation','TrustedToAuthForDelegation', 'PrimaryGroup','primaryGroupID',
                        'ProtectedFromAccidentalDeletion', 'OperatingSystem','OperatingSystemVersion', 'Description'
                    )
                    # servicePrincipalNames will contain subelements. Thus, it will not be iterated to create new XML elements. 
                    $properties = $basic_properties + "servicePrincipalNames"
                    $computer_list = Get-ADComputer -Filter *
                    foreach ($c in $computer_list) {
                        try {
                            $computer = Get-ADComputer -Identity $c.SamAccountName -Properties $properties
                            $xmlWriter.WriteStartElement("ADComputer")
                                # add all basic properties directly as new XML elements
                                foreach ($p in $basic_properties) {
                                    $xmlWriter.WriteElementString($p, [string] $computer."$p");
                                }
                                # add new sub Tags for all SPNs
                                $xmlWriter.WriteStartElement("servicePrincipalNames")
                                foreach ($s in $computer.ServicePrincipalNames) {
                                    $xmlWriter.WriteElementString("SPN", [string] $s);
                                }
                                $xmlWriter.WriteEndElement() # servicePrincipalNames
                            $xmlWriter.WriteEndElement() # ADComputer
                        } catch{
                            # Ignore this ADComputer object and try to parse the next. No Tag will be added for this one. 
                        }
                    }
                } catch {
                    # Failed executions will be ignored and no ADComputer tags will be added under ADComputerList
                }
                $xmlWriter.WriteEndElement() # ADComputerList

                $end_of_comp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            }

    
            #############################################################################################################
            #    Collecting information about domain Users
            #    Note: Failed executions will be ignored and no ADUser tags will be added to ADUserList
            #############################################################################################################
            if (Get-Command Get-ADUser  -ErrorAction SilentlyContinue) {
                Write-Host "[*] Collecting information about AD users." 
                $start_of_users = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                $xmlWriter.WriteStartElement("ADUserList")
                try{
                    # Set the properties to retrieve. $basic_properties will contain all properties that can be added as 
                    # new XML Element
                    $basic_properties = @(
                        'DistinguishedName', 'SID', 'SamAccountName', 'displayName', 'Description', 'GivenName',
                        'Surname', 'Name', 'SIDHistory', 'Enabled', 'BadLogonCount', 'BadPwdCount' , 'Created',
                        'LastBadPasswordAttempt', 'lastLogon', 'LastLogonDate', 'TrustedForDelegation',
                        'TrustedToAuthForDelegation', 'logonCount', 'LockedOut', 'PasswordExpired', 'PasswordLastSet',
                        'PasswordNeverExpires','PasswordNotRequired', 'pwdLastSet','Modified'
                    )
                    # MemberOf will contain subelements. Thus, it will not be iterated to create new XML elements. 
                    $properties = $basic_properties + "MemberOf"
                    $properties = $properties + 'msDS-AllowedToDelegateTo'
                    $user_list = Get-ADUser -Filter *
                    foreach ($u in $user_list) {
                        try{
                            $user = get-aduser -identity $u.samaccountname -Properties $properties
                            $xmlWriter.WriteStartElement("ADUser");
                            # add all basic properties directly as new XML elements
                            foreach ($p in $basic_properties) {
                                $xmlWriter.WriteElementString($p, [string] $user."$p");
                            }
                            $xmlWriter.WriteStartElement("MemberOf");
                            foreach ($m in $user.MemberOf) {
                                $xmlWriter.WriteElementString("Group", [string] $m);
                            }
                            $xmlWriter.WriteEndElement(); # MemberOf
                            $xmlWriter.WriteStartElement("msDS-AllowedToDelegateTo");
                            foreach ($s in $user."msDS-AllowedToDelegateTo") {
                                $xmlWriter.WriteElementString("SPN", [string] $s);
                            }
                            $xmlWriter.WriteEndElement(); # msDS-AllowedToDelegateTo
                            $xmlWriter.WriteEndElement(); # ADUser
                        } catch {
                            # Ignore this ADUser object and try to parse the next. No Tag will be added for this one. 
                        }
                    }
                } catch {
                    # Failed executions will be ignored and no ADUser tags will be added under ADUserList
                }
                $xmlWriter.WriteEndElement() # ADUserList     
                $end_of_users = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            }

            #############################################################################################################
            #    Collecting information about domain groups
            #    Note: Failed executions will be ignored and no ADGroup tags will be added to ADGroupList
            #############################################################################################################
            if (Get-Command Get-ADGroup  -ErrorAction SilentlyContinue) {
                Write-Host "[*] Collecting information about AD groups." 
                $start_of_groups = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                $xmlWriter.WriteStartElement("ADGroupList")
                try{
                    # Set the properties to retrieve. $basic_properties will contain all properties that can be added as 
                    # new XML Element
                    $properties = @('CN', 'Description', 'GroupCategory', 'GroupScope', 'SamAccountName', 'SID')
                    $group_list = Get-ADGroup -Filter * -Properties $properties
                    foreach ($g in $group_list) {
                        try{
                            $xmlWriter.WriteStartElement("ADGroup");
                            # add all properties directly as new XML elements
                            foreach ($p in $Properties) {
                                $xmlWriter.WriteElementString($p, [string] $g."$p");
                            }
                            $xmlWriter.WriteStartElement("Members");
                            Write-Host "[*] - Collecting members of group: $g.SamAccountName " 
                            try{
                                $members = Get-ADGroupMember -Identity $g.SamAccountName -ErrorAction SilentlyContinue
                                foreach ($m in $members) {
                                    try{
                                        $xmlWriter.WriteStartElement("Member");
                                        $xmlWriter.WriteAttributeString("SamAccountName", [string] $m.SamAccountName)
                                        $xmlWriter.WriteAttributeString("SID", [string] $m.SID)
                                        $xmlWriter.WriteAttributeString("name", [string] $m.Name)
                                        $xmlWriter.WriteAttributeString("distinguishedName", [string] $m.distinguishedName)
                                        $xmlWriter.WriteEndElement(); # Member
                                    }catch{
                                        # Ignore this Member object and try to parse the next. No Tag will be added for this one. 
                                    }
                                }
                            }catch{
                                # Failed executions will be ignored and no Member tags will be added to Members
                            }
                            $xmlWriter.WriteEndElement(); # Members
                            $xmlWriter.WriteEndElement(); # ADGroup         
                        } catch {
                            # Ignore this ADGroup object and try to parse the next. No Tag will be added for this one. 
                        }
                    }
                }catch {
                    # Failed executions will be ignored and no ADGroup tags will be added under ADGroupList
                }
                $xmlWriter.WriteEndElement() # ADGroupList
                $end_of_groups = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            }
            
        $xmlWriter.WriteEndElement() # DomainCollector
        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        $xmlWriter.Close()
   }
}catch {}

$end_of_script = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "[*] Script execution:"
Write-Host "[*] - started: $start_of_script"
Write-Host "[*] - finished: $end_of_script"

Write-Host "[*] Collection of domain controller list:"
Write-Host "[*] - started: $start_of_dc"
Write-Host "[*] - finished: $end_of_dc"

Write-Host "[*] Collection of computer list:"
Write-Host "[*] - started: $start_of_comp"
Write-Host "[*] - finished: $end_of_comp"

Write-Host "[*] Collection of user list: "
Write-Host "[*] - started: $start_of_users"
Write-Host "[*] - finished: $end_of_users"


Write-Host "[*] Collection of group list:"
Write-Host "[*] - started: $start_of_groups"
Write-Host "[*] - finished: $end_of_groups"
