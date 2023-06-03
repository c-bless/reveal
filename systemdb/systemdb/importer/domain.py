from ..models.activedirectory import ADDomain, ADUser, ADUserMembership, ADGroup, ADGroupMember, ADDomainController, ADForest
from ..models.activedirectory import ADForestSite, ADForestGlobalCatalog, ADComputer, ADDCServerRole, ADOperationMasterRole
from ..models.activedirectory import ADSPN, ADPasswordPolicy, ADTrust
from ..models.db import db


def import_domain_collector(root):
    if root.tag != "DomainCollector":
        return
    for c in root.getchildren():
        if c.tag == "ADDomain": domain = domain2db(c)
        if c.tag == "ADForest": forest = forest2db(c)
        if c.tag == "ADDomainControllerList":
            for dc in c.getchildren():
                if dc.tag == "ADDomainController":
                    dc2db(xml=dc, domain=domain, forest=forest)
        if c.tag == "ADComputerList":
            for comp in c.getchildren():
                if comp.tag == "ADComputer":
                    computer2db(xml=comp, domain=domain)
        if c.tag == "ADGroupList":
            for group in c.getchildren():
                if group.tag == "ADGroup":
                    group2db(xml=group, domain=domain)
        if c.tag == "ADUserList":
            for user in c.getchildren():
                if user.tag == "ADUser":
                    user2db(xml=user, domain=domain)
        if c.tag == "ADDefaultDomainPasswordPolicy":
            passwordPolicy2db(xml=c, domain=domain)
        if c.tag == "ADFineGrainedPasswordPolicies":
            for policy in c.getchildren():
                if policy.tag == "ADFineGrainedPasswordPolicy":
                    passwordPolicy2db(xml=policy, domain=domain, type="ADFineGrainedPasswordPolicy")
        if c.tag == "ADTrusts":
            trusts2db(xml=c, domain=domain)
        db.session.commit()



def domain2db(addomain):
    # <ADDomain>
    #         <Name>ot</Name>
    #         <NetBIOSName>OTL</NetBIOSName>
    #         <DomainMode>Windows2016Domain</DomainMode>
    #         <DNSRoot>ot.lab</DNSRoot>
    #         <DomainSID>S-1-5-21-2979221235-2529638109-2329603834</DomainSID>
    #         <RIDMaster>DC.ot.lab</RIDMaster>
    #         <PDCEmulator>DC.ot.lab</PDCEmulator>
    #         <ParentDomain />
    #         <Forest>ot.lab</Forest>
    #         <UsersContainer>CN=Users,DC=ot,DC=lab</UsersContainer>
    #         <SystemsContainer>CN=System,DC=ot,DC=lab</SystemsContainer>
    #         <ComputersContainer>CN=Computers,DC=ot,DC=lab</ComputersContainer>
    #         <DistinguishedName>DC=ot,DC=lab</DistinguishedName>
    #         <InfrastructureMaster>DC.ot.lab</InfrastructureMaster>
    #     </ADDomain>
    dom = ADDomain()
    for e in addomain.getchildren():
        if "Name" == e.tag: dom.Name = e.text
        if "NetBIOSName" == e.tag: dom.NetBIOSName = e.text
        if "DomainMode" == e.tag: dom.DomainMode = e.text
        if "DNSRoot" == e.tag: dom.DNSRoot = e.text
        if "DomainSID" == e.tag: dom.DomainSID = e.text
        if "RIDMaster" == e.tag: dom.RIDMaster = e.text
        if "PDCEmulator" == e.tag: dom.PDCEmulator = e.text
        if "ParentDomain" == e.tag: dom.ParentDomain = e.text
        if "ParentDomain" == e.tag: dom.ParentDomain = e.text
        if "Forest" == e.tag: dom.Forest = e.text
        if "UsersContainer" == e.tag: dom.UsersContainer = e.text
        if "SystemsContainer" == e.tag: dom.SystemsContainer = e.text
        if "ComputersContainer" == e.tag: dom.ComputersContainer = e.text
        if "DistinguishedName" == e.tag: dom.DistinguishedName = e.text
        if "InfrastructureMaster" == e.tag: dom.InfrastructureMaster = e.text
    db.session.add(dom)
    db.session.commit()
    db.session.refresh(dom)
    return dom


def forest2db(adforest):
    #<forest>
    #    <DomainNamingMaster>DC.ot.lab</DomainNamingMaster>
    #    <Name>ot.lab</Name>
    #    <RootDomain>ot.lab</RootDomain>
    #    <SchemaMaster>DC.ot.lab</SchemaMaster>
    #    <sites>
    #        <site />
    #    </sites>
    #    <GlobalCatalogs>
    #        <GlobalCatalog>DC.ot.lab</GlobalCatalog>
    #    </GlobalCatalogs>
    #</forest>ad
    forest = ADForest()
    for e in adforest.getchildren():
        if "Name" == e.tag: forest.Name = e.text
        if "DomainNamingMaster" == e.tag: forest.DomainNamingMaster = e.text
        if "RootDomain" == e.tag: forest.RootDomain = e.text
        if "SchemaMaster" == e.tag: forest.SchemaMaster = e.text
    db.session.add(forest)
    db.session.commit()
    db.session.refresh(forest)
    if "Sites" == e.tag:
        for s in e.getchildren():
            if "Site" == s.tag:
                if (len(s.text) > 0):
                    site = ADForestSite()
                    site.Site = s.text
                    site.Forest_id = forest.id
                    db.session.add(site)
    if "GlobalCatalogs" == e.tag:
        for g in e.getchildren():
            if "GlobalCatalog" == g.tag:
                gc = ADForestGlobalCatalog()
                gc.GlobalCatalog = g.text
                gc.Forest_id = forest.id
                db.session.add(gc)
    db.session.commit()
    return forest


def passwordPolicy2db(xml, domain, type="ADDefaultDomainPasswordPolicy"):
    policy = ADPasswordPolicy()
    policy.Domain_id = domain.id
    policy.Type = type
    for e in xml.getchildren():
        if "ComplexityEnabled" == e.tag: policy.ComplexityEnabled = e.text
        if "DistinguishedName" == e.tag: policy.DistinguishedName = e.text
        if "LockoutDuration" == e.tag: policy.LockoutDuration = e.text
        if "LockoutObservationWindow" == e.tag: policy.LockoutObservationWindow = e.text
        if "LockoutThreshold" == e.tag: policy.LockoutThreshold = e.text
        if "MaxPasswordAge" == e.tag: policy.MaxPasswordAge = e.text
        if "MinPasswordAge" == e.tag: policy.MinPasswordAge = e.text
        if "MinPasswordLength" == e.tag: policy.MinPasswordLength = e.text
        if "PasswordHistoryCount" == e.tag: policy.PasswordHistoryCount = e.text
        if "ReversibleEncryptionEnabled" == e.tag: policy.ReversibleEncryptionEnabled = e.text
        if "Name" == e.tag:
            if type == "ADDefaultDomainPasswordPolicy":
                policy.Name = type
            else:
                policy.Name = e.text
    db.session.add(policy)
    #db.session.commit()


def dc2db(xml, domain, forest):
    dc = ADDomainController()
    dc.Domain_id = domain.id
    dc.Forest_id = forest.id
    for e in xml.getchildren():
        if "Name" == e.tag: dc.Name = e.text
        if "Hostname" == e.tag: dc.Hostname = e.text
        if "OperatingSystem" == e.tag: dc.OperatingSystem = e.text
        if "IPv4Address" == e.tag: dc.IPv4Address = e.text
        if "IPv6Address" == e.tag: dc.IPv6Address = e.text
        if "Enabled" == e.tag: dc.Enabled = e.text
        if "Domain" == e.tag: dc.Domain = e.text
        if "Forest" == e.tag: dc.Forest = e.text
        if "IsGlobalCatalog" == e.tag: dc.IsGlobalCatalog = e.text
        if "IsReadOnly" == e.tag: dc.IsReadOnly = e.text
        if "LdapPort" == e.tag: dc.LdapPort = e.text
        if "SslPort" == e.tag: dc.SslPort = e.text
    db.session.add(dc)
    db.session.commit()
    db.session.refresh(dc)
    for e in xml.getchildren():
        if "ServerRoles" == e.tag:
            for s in e.getchildren():
                if "Role" == s.tag:
                    role = ADDCServerRole()
                    role.Role = s.text
                    role.DC_id = dc.id
                    db.session.add(role)
        if "OperationMasterRoles" == e.tag:
            for s in e.getchildren():
                if "Role" == s.tag:
                    role = ADOperationMasterRole()
                    role.Role = s.text
                    role.DC_id = dc.id
                    db.session.add(role)

    #db.session.commit()


def computer2db(xml, domain):
    c = ADComputer()
    c.Domain_id = domain.id
    for e in xml.getchildren():
        if "DistinguishedName" == e.tag: c.DistinguishedName = e.text
        if "DNSHostName" == e.tag: c.DNSHostName = e.text
        if "Enabled" == e.tag: c.Enabled = e.text
        if "IPv4Address" == e.tag: c.IPv4Address = e.text
        if "IPv6Address" == e.tag: c.IPv6Address = e.text
        if "SID" == e.tag: c.SID = e.text
        if "SamAccountName" == e.tag: c.SamAccountName = e.text
        if "ServiceAccount" == e.tag: c.ServiceAccount = e.text
        if "servicePrincipalNamesStr" == e.tag: c.servicePrincipalNamesStr = e.text
        if "TrustedForDelegation" == e.tag: c.TrustedForDelegation = e.text
        if "TrustedToAuthForDelegation" == e.tag: c.TrustedToAuthForDelegation = e.text
        if "PrimaryGroup" == e.tag: c.PrimaryGroup = e.text
        if "primaryGroupID" == e.tag: c.primaryGroupID = e.text
        if "pwdLastSet" == e.tag: c.pwdLastSet = e.text
        if "ProtectedFromAccidentalDeletion" == e.tag: c.ProtectedFromAccidentalDeletion = e.text
        if "OperatingSystem" == e.tag: c.OperatingSystem = e.text
        if "OperatingSystemVersion" == e.tag: c.OperatingSystemVersion = e.text
        if "Description" == e.tag: c.Description = e.text
    c.Domain_id = domain.id
    db.session.add(c)
    db.session.commit()
    db.session.refresh(c)
    for e in xml.getchildren():
        if "servicePrincipalNames" == e.tag:
            for s in e.getchildren():
                if "SPN" == s.tag:
                    spn = ADSPN()
                    spn.Name = s.text
                    spn.Computer_id = c.id
                    db.session.add(spn)

    #db.session.commit()


def user2db(xml, domain):
    user = ADUser()
    user.Domain_id = domain.id
    for e in xml.getchildren():
        if "SamAccountName" == e.tag: user.SAMAccountName = e.text
        if "SAMAccountName" == e.tag: user.SAMAccountName = e.text
        if "DistinguishedName" == e.tag: user.DistinguishedName = e.text
        if "SID" == e.tag: user.SID = e.text
        if "Surname" == e.tag: user.Surname = e.text
        if "Name" == e.tag: user.Name = e.text
        if "SIDHistory" == e.tag: user.SIDHistory = e.text
        if "Enabled" == e.tag: user.Enabled = e.text
        if "Description" == e.tag: user.Description = e.text
        if "DistinguishedName" == e.tag: user.DistinguishedName = e.text
        if "BadLogonCount" == e.tag: user.BadLogonCount = e.text
        if "BadPwdCount" == e.tag: user.BadPwdCount = e.text
        if "Created" == e.tag: user.Created = e.text
        if "LastBadPasswordAttempt" == e.tag: user.LastBadPasswordAttempt = e.text
        if "lastLogon" == e.tag: user.lastLogon = e.text
        if "LastLogonDate" == e.tag: user.LastLogonDate = e.text
        if "logonCount" == e.tag: user.logonCount = e.text
        if "LockedOut" == e.tag: user.LockedOut = e.text
        if "PasswordExpired" == e.tag: user.PasswordExpired = e.text
        if "PasswordLastSet" == e.tag: user.PasswordLastSet = e.text
        if "PasswordNeverExpires" == e.tag: user.PasswordNeverExpires = e.text
        if "PasswordNotRequired" == e.tag: user.PasswordNotRequired = e.text
        if "pwdLastSet" == e.tag: user.pwdLastSet = e.text
        if "Modified" == e.tag: user.Modified = e.text
        if "MemberOfStr" == e.tag: user.MemberOfStr = e.text
    db.session.add(user)
    db.session.commit()
    db.session.refresh(user)
    for e in xml.getchildren():
        if "MemberOf" == e.tag:
            for m in e.getchildren():
                if "Group" == m.tag:
                    group = ADUserMembership()
                    group.Group = m.text
                    group.User_id = user.id
                    db.session.add(group)
    #db.session.commit()


def group2db(xml, domain):
    group = ADGroup()
    group.Domain_id = domain.id
    for e in xml.getchildren():
        if "CN" == e.tag: group.CN = e.text
        if "Description" == e.tag: group.Description = e.text
        if "GroupCategory" == e.tag: group.GroupCategory = e.text
        if "GroupScope" == e.tag: group.GroupScope = e.text
        if "SamAccountName" == e.tag: group.SamAccountName = e.text
        if "SID" == e.tag: group.SID = e.text
        if "MemberOfStr" == e.tag: group.MemberOfStr = e.text
    db.session.add(group)
    db.session.commit()
    db.session.refresh(group)
    for e in xml.getchildren():
        if "Members" == e.tag:
            for m in e.getchildren():
                if "Member" == m.tag:
                    member = ADGroupMember()
                    member.SamAccountName = m.get("SamAccountName")
                    member.SID = m.get("SID")
                    member.Name = m.get("name")
                    member.distinguishedName = m.get("distinguishedName")
                    member.Group_id = group.id
                    db.session.add(member)
    #db.session.commit()


def trusts2db(xml, domain):
    for t in xml.getchildren():
        if t.tag == "ADTrust":
            trust = ADTrust()
            trust.Domain_id = domain.id
            for e in t.getchildren():
                if "Source" == e.tag: trust.Source = e.text
                if "Target" == e.tag: trust.Target = e.text
                if "Direction" == e.tag: trust.Direction = e.text
                if "TrustType" == e.tag: trust.TrustType = e.text
                if "UplevelOnly" == e.tag: trust.UplevelOnly = e.text
                if "UsesAESKeys" == e.tag: trust.UsesAESKeys = e.text
                if "UsesRC4Encryption" == e.tag: trust.UsesRC4Encryption = e.text
                if "TGTDelegation" == e.tag: trust.TGTDelegation = e.text
                if "SIDFilteringForestAware" == e.tag: trust.SIDFilteringForestAware = e.text
                if "SIDFilteringQuarantined" == e.tag: trust.SIDFilteringQuarantined = e.text
                if "SelectiveAuthentication" == e.tag: trust.SelectiveAuthentication = e.text
                if "DisallowTransivity" == e.tag: trust.DisallowTransivity = e.text
                if "DistinguishedName" == e.tag: trust.DistinguishedName = e.text
                if "ForestTransitive" == e.tag: trust.ForestTransitive = e.text
                if "IntraForest" == e.tag: trust.IntraForest = e.text
                if "IsTreeParent" == e.tag: trust.IsTreeParent = e.text
                if "IsTreeRoot" == e.tag: trust.IsTreeRoot = e.text
            db.session.add(trust)
    #db.session.commit()