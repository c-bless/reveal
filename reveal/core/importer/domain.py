from sqlalchemy.exc import SQLAlchemyError
from reveal.core.extentions import db

from reveal.core.models.activedirectory import ADDomain
from reveal.core.models.activedirectory import ADUser
from reveal.core.models.activedirectory import ADUserMembership
from reveal.core.models.activedirectory import ADUserAuthDelegationSPN
from reveal.core.models.activedirectory import ADGroup
from reveal.core.models.activedirectory import ADGroupMember
from reveal.core.models.activedirectory import ADDomainController
from reveal.core.models.activedirectory import ADForest
from reveal.core.models.activedirectory import ADForestSite
from reveal.core.models.activedirectory import ADForestGlobalCatalog
from reveal.core.models.activedirectory import ADComputer
from reveal.core.models.activedirectory import ADDCServerRole
from reveal.core.models.activedirectory import ADOperationMasterRole
from reveal.core.models.activedirectory import ADUserServicePrincipalName
from reveal.core.models.activedirectory import ADSPN
from reveal.core.models.activedirectory import ADPasswordPolicy
from reveal.core.models.activedirectory import ADTrust

from reveal.core.importer.converter import str2bool_or_none
from reveal.core.importer.converter import ts2datetime_or_none
from reveal.core.importer.converter import str2int_or_none


def import_domain_collector(root):
    if root.tag != "DomainCollector":
        return
    domain = None
    forest = None
    for c in root.getchildren():
        if c.tag == "ADDomain": domain = domain2db(c)
        if c.tag == "ADForest": forest = forest2db(c)
    for c in root.getchildren():
        if c.tag == "ADDomainControllerList":
            for dc in c.getchildren():
                if dc.tag == "ADDomainController":
                    try:
                        dc2db(xml=dc, domain=domain, forest=forest)
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        error = str(e.__dict__['orig'])
                        print("Error while importing ADDomainController")
                        print(error)
        if c.tag == "ADComputerList":
            for comp in c.getchildren():
                if comp.tag == "ADComputer":
                    try:
                        computer2db(xml=comp, domain=domain)
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        print("Error while importing ADComputer")
                        error = str(e.__dict__['orig'])
                        print(error)
        if c.tag == "ADGroupList":
            for group in c.getchildren():
                if group.tag == "ADGroup":
                    try:
                        group2db(xml=group, domain=domain)
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        print("Error while importing ADGroup")
                        error = str(e.__dict__['orig'])
                        print(error)
        if c.tag == "ADUserList":
            for user in c.getchildren():
                if user.tag == "ADUser":
                    try:
                        user2db(xml=user, domain=domain)
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        print("Error while importing ADUser")
                        error = str(e.__dict__['orig'])
                        print(error)
        if c.tag == "ADUserAddon":
            userAddons2db(xml=c, domain=domain)
        if c.tag == "ADDefaultDomainPasswordPolicy":
            try:
                passwordPolicy2db(xml=c, domain=domain)
            except SQLAlchemyError as e:
                db.session.rollback()
                print("Error while importing ADDefaultDomainPasswordPolicy")
                error = str(e.__dict__['orig'])
                print(error)
        if c.tag == "ADFineGrainedPasswordPolicies":
            for policy in c.getchildren():
                if policy.tag == "ADFineGrainedPasswordPolicy":
                    try:
                        passwordPolicy2db(xml=policy, domain=domain, type="ADFineGrainedPasswordPolicy")
                    except SQLAlchemyError as e:
                        db.session.rollback()
                        print("Error while importing ADFineGrainedPasswordPolicy")
                        error = str(e.__dict__['orig'])
                        print(error)
        if c.tag == "ADTrusts":
            try:
                trusts2db(xml=c, domain=domain)
            except SQLAlchemyError as e:
                db.session.rollback()
                print("Error while importing ADTrusts")
                error = str(e.__dict__['orig'])
                print(error)
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
    try:
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
    except SQLAlchemyError as e:
        db.session.rollback()
        error = str(e.__dict__['orig'])
        print(error)
        return None


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
    try:
        forest = ADForest()
        for e in adforest.getchildren():
            if "Name" == e.tag: forest.Name = e.text
            if "DomainNamingMaster" == e.tag: forest.DomainNamingMaster = e.text
            if "RootDomain" == e.tag: forest.RootDomain = e.text
            if "SchemaMaster" == e.tag: forest.SchemaMaster = e.text
        db.session.add(forest)
        for e in adforest.getchildren():
            if "Sites" == e.tag:
                for s in e.getchildren():
                    if "Site" == s.tag:
                        if len(s.text) > 0:
                            site = ADForestSite()
                            site.Site = s.text
                            site.Forest = forest
                            db.session.add(site)
            if "GlobalCatalogs" == e.tag:
                for g in e.getchildren():
                    if "GlobalCatalog" == g.tag:
                        gc = ADForestGlobalCatalog()
                        gc.GlobalCatalog = g.text
                        gc.Forest = forest
                        db.session.add(gc)
        db.session.commit()
        db.session.refresh(forest)
        return forest
    except SQLAlchemyError as e:
        db.session.rollback()
        error = str(e.__dict__['orig'])
        print(error)
        return None


def passwordPolicy2db(xml, domain, type="ADDefaultDomainPasswordPolicy"):
    policy = ADPasswordPolicy()
    policy.Domain= domain
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
    dc.Domain = domain
    dc.Forest = forest
    for e in xml.getchildren():
        if "Name" == e.tag: dc.Name = e.text
        if "Hostname" == e.tag: dc.Hostname = e.text
        if "OperatingSystem" == e.tag: dc.OperatingSystem = e.text
        if "IPv4Address" == e.tag: dc.IPv4Address = e.text
        if "IPv6Address" == e.tag: dc.IPv6Address = e.text
        if "Enabled" == e.tag: dc.Enabled = str2bool_or_none(e.text)
        if "Domainname" == e.tag: dc.Domainname = e.text
        if "Forestname" == e.tag: dc.Forestname = e.text
        if "IsGlobalCatalog" == e.tag: dc.IsGlobalCatalog = str2bool_or_none(e.text)
        if "IsReadOnly" == e.tag: dc.IsReadOnly = str2bool_or_none(e.text)
        if "LdapPort" == e.tag: dc.LdapPort = int(e.text)
        if "SslPort" == e.tag: dc.SslPort = int(e.text)
    db.session.add(dc)
    for e in xml.getchildren():
        if "ServerRoles" == e.tag:
            for s in e.getchildren():
                if "Role" == s.tag:
                    role = ADDCServerRole()
                    role.Role = s.text
                    role.DC = dc
                    db.session.add(role)
        if "OperationMasterRoles" == e.tag:
            for s in e.getchildren():
                if "Role" == s.tag:
                    role = ADOperationMasterRole()
                    role.Role = s.text
                    role.DC = dc
                    db.session.add(role)
    db.session.commit()


def computer2db(xml, domain):
    c = ADComputer()
    c.Domain = domain
    for e in xml.getchildren():
        if "DistinguishedName" == e.tag: c.DistinguishedName = e.text
        if "DNSHostName" == e.tag: c.DNSHostName = e.text
        if "Enabled" == e.tag: c.Enabled = str2bool_or_none(e.text)
        if "IPv4Address" == e.tag: c.IPv4Address = e.text
        if "IPv6Address" == e.tag: c.IPv6Address = e.text
        if "SID" == e.tag: c.SID = e.text
        if "SamAccountName" == e.tag: c.SamAccountName = e.text
        if "ServiceAccount" == e.tag: c.ServiceAccount = e.text
        if "servicePrincipalNamesStr" == e.tag: c.servicePrincipalNamesStr = e.text
        if "TrustedForDelegation" == e.tag: c.TrustedForDelegation = str2bool_or_none(e.text)
        if "TrustedToAuthForDelegation" == e.tag: c.TrustedToAuthForDelegation = str2bool_or_none(e.text)
        if "PrimaryGroup" == e.tag: c.PrimaryGroup = e.text
        if "primaryGroupID" == e.tag: c.primaryGroupID = e.text
        if "pwdLastSet" == e.tag: c.pwdLastSet = e.text
        if "ProtectedFromAccidentalDeletion" == e.tag: c.ProtectedFromAccidentalDeletion = str2bool_or_none(e.text)
        if "OperatingSystem" == e.tag: c.OperatingSystem = e.text
        if "OperatingSystemVersion" == e.tag: c.OperatingSystemVersion = e.text
        if "Description" == e.tag: c.Description = e.text
    db.session.add(c)
    for e in xml.getchildren():
        if "servicePrincipalNames" == e.tag:
            for s in e.getchildren():
                if "SPN" == s.tag:
                    spn = ADSPN()
                    spn.Name = s.text
                    spn.Computer = c
                    db.session.add(spn)
    db.session.commit()


def userTrustedForDel2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            trusted4del = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "TrustedForDelegation" == e.tag: trusted4del = str2bool_or_none(e.text)
            if samaccountname is None:
                continue
            try:
                db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).update(
                    {ADUser.TrustedForDelegation: trusted4del})
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing TrustedForDelegation on ADUserAddon")


def userTrustedToAuthForDel2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            trusted4del = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "TrustedToAuthForDelegation" == e.tag: trusted4del = str2bool_or_none(e.text)
            if samaccountname is None:
                continue
            try:
                for e in x.getchildren():
                    if "msDS-AllowedToDelegateTo" == e.tag:
                        user = db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).first()
                        user.TrustedToAuthForDelegation = trusted4del
                        for s in e.getchildren():
                            if "SPN" == s.tag:
                                spn = ADUserAuthDelegationSPN()
                                spn.SPN = s.text
                                spn.User = user
                                db.session.add(spn)
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing TrustedToAuthForDelegation on ADUserAddon")


def userPasswordNeverExpires2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            pw_expires = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "PasswordNeverExpires" == e.tag: pw_expires = str2bool_or_none(e.text)
            if samaccountname is None:
                continue
            try:
                db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).update(
                    {ADUser.PasswordNeverExpires: pw_expires})
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing PasswordNeverExpires on ADUserAddon")


def userPasswordNotRequired2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            pw_req = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "PasswordNotRequired" == e.tag: pw_req = str2bool_or_none(e.text)
            if samaccountname is None:
                continue
            try:
                db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).update(
                    {ADUser.PasswordNotRequired: pw_req})
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing PasswordNotRequired on ADUserAddon")


def userAdminSDHolder2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            sdholder = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "AdminSDHolder" == e.tag: sdholder = str2bool_or_none(e.text)
            if samaccountname is None:
                continue
            try:
                db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).update(
                    {ADUser.AdminSDHolder: sdholder})
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing AdminSDHolder on ADUserAddon")


def userAccountNotDelegated2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            notdelegated = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "AccountNotDelegated" == e.tag: notdelegated = str2bool_or_none(e.text)
            if samaccountname is None:
                continue
            try:
                db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).update(
                    {ADUser.AccountNotDelegated: notdelegated})
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing AccountNotDelegated on ADUserAddon")


def userLogonWorkstations2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            workstations = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "logonworkstations" == e.tag: workstations = str(e.text)
            if samaccountname is None:
                continue
            try:
                db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).update(
                    {ADUser.LogonWorkstations: workstations})
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing SIDHistory on ADUserAddon")


def userSIDHistory2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            history = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
                if "SIDHistory" == e.tag: history = str(e.text)
            if samaccountname is None:
                continue
            try:
                db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).update(
                    {ADUser.SIDHistory: history})
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing SIDHistory on ADUserAddon")


def userServicePrincipalName2db(xml, domain):
    for x in xml.getchildren():
        if "ADUser" == x.tag:
            samaccountname = None
            for e in x.getchildren():
                if "SamAccountName" == e.tag: samaccountname = e.text
            if samaccountname is None:
                continue
            try:
                for sname in x.getchildren():
                    if "ServicePrincipalName" == sname.tag:
                        user = db.session.query(ADUser).filter(ADUser.SAMAccountName == samaccountname).first()
                        for s in sname.getchildren():
                            if "SPN" == s.tag:
                                spn = ADUserServicePrincipalName()
                                spn.SPN = s.text
                                spn.User = user
                                db.session.add(spn)
                db.session.commit()
            except SQLAlchemyError as er:
                db.session.rollback()
                print("Error while importing ServicePrincipalName on ADUserAddon")


def userAddons2db(xml, domain):
    for x in xml.getchildren():
        if "TrustedForDelegationList" == x.tag:
            try:
                userTrustedForDel2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "TrustedToAuthForDelegationList" == x.tag:
            try:
                userTrustedToAuthForDel2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "AccountNotDelegatedList" == x.tag:
            try:
                userAccountNotDelegated2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "PasswordNotRequiredList" == x.tag:
            try:
                userPasswordNotRequired2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "PasswordNeverExpiresList" == x.tag:
            try:
                userPasswordNeverExpires2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "logonworkstationsList" == x.tag:
            try:
                userLogonWorkstations2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "ServicePrincipalNameList" == x.tag:
            try:
                userServicePrincipalName2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "SIDHistoryList" == x.tag:
            try:
                userSIDHistory2db(xml=x, domain=domain)
            except Exception as error:
                print(error)
        if "AdminSDHolderList" == x.tag:
            try:
                userAdminSDHolder2db(xml=x, domain=domain)
            except Exception as error:
                print(error)


def user2db(xml, domain):
    user = ADUser()
    user.Domain = domain
    for e in xml.getchildren():
        if "SamAccountName" == e.tag: user.SAMAccountName = e.text
        if "SAMAccountName" == e.tag: user.SAMAccountName = e.text
        if "DistinguishedName" == e.tag: user.DistinguishedName = e.text
        if "SID" == e.tag: user.SID = e.text
        if "Surname" == e.tag: user.Surname = e.text
        if "Name" == e.tag: user.Name = e.text
        if "SIDHistory" == e.tag: user.SIDHistory = e.text
        if "Enabled" == e.tag: user.Enabled = str2bool_or_none(e.text)
        if "Description" == e.tag: user.Description = e.text
        if "DistinguishedName" == e.tag: user.DistinguishedName = e.text
        if "displayName" == e.tag: user.DisplayName = e.text
        if "BadLogonCount" == e.tag: user.BadLogonCount = str2int_or_none(e.text)
        if "BadPwdCount" == e.tag: user.BadPwdCount = str2int_or_none(e.text)
        if "Created" == e.tag: user.Created = e.text
        if "LastBadPasswordAttempt" == e.tag: user.LastBadPasswordAttempt = e.text
        if "lastLogon" == e.tag and e.text: user.lastLogon = ts2datetime_or_none(int(e.text))
        if "LastLogonDate" == e.tag: user.LastLogonDate = e.text
        if "logonCount" == e.tag: user.logonCount = str2int_or_none(e.text)
        if "LockedOut" == e.tag: user.LockedOut = str2bool_or_none(e.text)
        if "PasswordExpired" == e.tag: user.PasswordExpired = str2bool_or_none(e.text)
        if "PasswordLastSet" == e.tag: user.PasswordLastSet = e.text
        if "PasswordNeverExpires" == e.tag: user.PasswordNeverExpires = str2bool_or_none(e.text)
        if "PasswordNotRequired" == e.tag: user.PasswordNotRequired = str2bool_or_none(e.text)
        if "pwdLastSet" == e.tag: user.pwdLastSet = ts2datetime_or_none(e.text)
        if "Modified" == e.tag: user.Modified = e.text
        if "MemberOfStr" == e.tag: user.MemberOfStr = e.text
        if "TrustedForDelegation" == e.tag: user.TrustedForDelegation = str2bool_or_none(e.text)
        if "TrustedToAuthForDelegation" == e.tag: user.TrustedToAuthForDelegation = str2bool_or_none(e.text)
    db.session.add(user)
    for e in xml.getchildren():
        if "MemberOf" == e.tag:
            for m in e.getchildren():
                if "Group" == m.tag:
                    group = ADUserMembership()
                    group.Group = m.text
                    group.User = user
                    db.session.add(group)
        if "msDS-AllowedToDelegateTo" == e.tag:
            for s in e.getchildren():
                if "SPN" == s.tag:
                    spn = ADUserAuthDelegationSPN()
                    spn.SPN = s.text
                    spn.User = user
                    db.session.add(spn)
    db.session.commit()


def group2db(xml, domain):
    group = ADGroup()
    group.Domain = domain
    for e in xml.getchildren():
        if "CN" == e.tag: group.CN = e.text
        if "Description" == e.tag: group.Description = e.text
        if "GroupCategory" == e.tag: group.GroupCategory = e.text
        if "GroupScope" == e.tag: group.GroupScope = e.text
        if "SamAccountName" == e.tag: group.SamAccountName = e.text
        if "SID" == e.tag: group.SID = e.text
        if "MemberOfStr" == e.tag: group.MemberOfStr = e.text
    db.session.add(group)
    for e in xml.getchildren():
        if "Members" == e.tag:
            for m in e.getchildren():
                if "Member" == m.tag:
                    member = ADGroupMember()
                    member.SamAccountName = m.get("SamAccountName")
                    member.SID = m.get("SID")
                    member.Name = m.get("name")
                    member.distinguishedName = m.get("distinguishedName")
                    member.Group = group
                    db.session.add(member)
    db.session.commit()


def trusts2db(xml, domain):
    for t in xml.getchildren():
        if t.tag == "ADTrust":
            trust = ADTrust()
            trust.Domain = domain
            for e in t.getchildren():
                if "Source" == e.tag: trust.Source = e.text
                if "Target" == e.tag: trust.Target = e.text
                if "Direction" == e.tag: trust.Direction = e.text
                if "TrustType" == e.tag: trust.TrustType = e.text
                if "UplevelOnly" == e.tag: trust.UplevelOnly = str2bool_or_none(e.text)
                if "UsesAESKeys" == e.tag: trust.UsesAESKeys = str2bool_or_none(e.text)
                if "UsesRC4Encryption" == e.tag: trust.UsesRC4Encryption = str2bool_or_none(e.text)
                if "TGTDelegation" == e.tag: trust.TGTDelegation = str2bool_or_none(e.text)
                if "SIDFilteringForestAware" == e.tag: trust.SIDFilteringForestAware = str2bool_or_none(e.text)
                if "SIDFilteringQuarantined" == e.tag: trust.SIDFilteringQuarantined = str2bool_or_none(e.text)
                if "SelectiveAuthentication" == e.tag: trust.SelectiveAuthentication = str2bool_or_none(e.text)
                if "DisallowTransivity" == e.tag: trust.DisallowTransivity = str2bool_or_none(e.text)
                if "DistinguishedName" == e.tag: trust.DistinguishedName = e.text
                if "ForestTransitive" == e.tag: trust.ForestTransitive = str2bool_or_none(e.text)
                if "IntraForest" == e.tag: trust.IntraForest = str2bool_or_none(e.text)
                if "IsTreeParent" == e.tag: trust.IsTreeParent = str2bool_or_none(e.text)
                if "IsTreeRoot" == e.tag: trust.IsTreeRoot = str2bool_or_none(e.text)
            db.session.add(trust)
    db.session.commit()
