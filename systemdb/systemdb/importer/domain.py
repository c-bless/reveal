from ..core.model import ADDomain, ADUser, ADUserMembership, ADGroup, ADGroupMember, ADDomainController, ADForest, ADForestSite, ADForestGlobalCatalog, ADComputer, ADDCServerRole, ADOperationMasterRole, ADSPN
from ..core.db import db

def import_domain(filename):
    from lxml import etree

    with open(filename, 'r') as f:
        xml = f.read()

    root = etree.fromstring(xml)

    for c in root.getchildren():
        if c.tag == "ADDomain": domain = domain2db(c)
        if c.tag == "ADForest": forest = forest2db(c)
        if c.tag == "ADDomainControllerList":
            for dc in c.getchildren():
                if dc.tag == "ADDomainController":
                    dc2db(dc, domain)
        if c.tag == "ADComputerList":
            for comp in c.getchildren():
                if comp.tag == "ADComputer":
                    computer2db(comp, domain)
        if c.tag == "ADGroupList":
            for group in c.getchildren():
                if group.tag == "ADGroup":
                    group2db(group)
        if c.tag == "ADUserList":
            for user in c.getchildren():
                if user.tag == "ADUser":
                    user2db(user)
        #forest_element = c.getElementsByTagName("forest")
        #forest = forest2db(forest_element=forest_element)


def domain2db(addomain):
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
            if "Site" == e.tag:
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

def dc2db(addc, domain):

    dc = ADDomainController()
    for e in addc.getchildren():
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
    for e in addc.getchildren():
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

    db.session.commit()


def computer2db(computer, domain):
    c = ADComputer()
    for e in computer.getchildren():
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
    for e in computer.getchildren():
        if "servicePrincipalNames" == e.tag:
            for s in e.getchildren():
                if "SPN" == s.tag:
                    spn = ADSPN()
                    spn.Name = s.text
                    spn.Computer_id = c.id
                    db.session.add(spn)

    db.session.commit()



def user2db(xml):
    user = ADUser()
    for e in xml.getchildren():
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
    db.session.commit()



def group2db(xml):
    group = ADGroup()
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
    db.session.commit()